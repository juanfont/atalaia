package llm

import (
	"context"
	"fmt"
)

// completeParsed retries an incomplete/malformed completion once, from scratch,
// within the SAME deadline and output budget. Valid semantic decisions are never
// retried. Partial output is never merged into the successful replacement.
func completeParsed[T any](ctx context.Context, client ChatCompleter, req ChatRequest, parse func(Message) ([]T, error)) ([]T, int, error) {
	for calls := 1; calls <= 2; calls++ {
		if err := ctx.Err(); err != nil {
			return nil, calls - 1, err
		}
		resp, err := client.Complete(ctx, req)
		if err != nil {
			return nil, calls, err
		}
		failure := "empty choices"
		finish := "missing"
		if len(resp.Choices) > 0 {
			choice := resp.Choices[0]
			finish = safeFinishReason(choice.FinishReason)
			switch finish {
			case "content_filter":
				return nil, calls, fmt.Errorf("model response refused (finish_reason=content_filter)")
			case "length":
				failure = "truncated"
			default:
				parsed, err := parse(choice.Message)
				if err == nil {
					return parsed, calls, nil
				}
				failure = "malformed"
			}
		}
		if calls == 2 {
			// Model text, tool arguments and parser errors may contain secrets.
			return nil, calls, fmt.Errorf("model response %s after %d attempts (finish_reason=%s, completion_tokens=%d)", failure, calls, finish, resp.Usage.CompletionTokens)
		}
		// Copy the slice before appending: never mutate the caller's prompt.
		req.Messages = append(append([]Message(nil), req.Messages...), Message{Role: "user", Content: "The previous response was incomplete or invalid. Return one complete response using the required schema and tool, with concise reasons and all required items. Copy credential values exactly. For private keys, return only the BEGIN header, never the body. Do not include commentary or repeat output."})
	}
	panic("unreachable")
}

func safeFinishReason(reason string) string {
	switch reason {
	case "", "stop", "length", "tool_calls", "function_call", "content_filter":
		return reason
	default:
		return "other"
	}
}
