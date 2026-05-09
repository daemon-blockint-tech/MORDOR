from __future__ import annotations


from agents.gates import skip_llm
from agents.schemas import GimliTraceSchema
from tools.openrouter_client import chat_structured


def trace_binary(binary_path: str, breakpoints: list[str] | None = None, tier: str = "standard") -> dict:
    bps = breakpoints or []

    if not skip_llm(tier):
        messages = [
            {
                "role": "system",
                "content": "You are GIMLI, a debugger agent (x64dbg on Windows, LLDB/GDB elsewhere). "
                "Given a binary and optional breakpoints, describe the debugging "
                "session setup and expected trace results.",
            },
            {
                "role": "user",
                "content": f"Set up debugging session for: {binary_path}\nBreakpoints: {bps}",
            },
        ]
        result = chat_structured(
            messages, schema=GimliTraceSchema,
            temperature=0.3, agent_name="gimli", phase="validate",
        )
        if result is not None:
            return result.model_dump()
    return {"breakpoints": bps, "trace_log": [], "status": "llm_failed"}
