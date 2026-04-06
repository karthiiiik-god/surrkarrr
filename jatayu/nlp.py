from memory import load_memory, save_memory

def process_query(query, memory):
    query = query.lower()
    if "hello" in query or "hi" in query:
        return "Hello! How can I assist you today?"
    elif "time" in query:
        from datetime import datetime
        return f"The current time is {datetime.now().strftime('%H:%M:%S')}"
    elif "date" in query:
        from datetime import datetime
        return f"Today's date is {datetime.now().strftime('%Y-%m-%d')}"
    elif "shutdown" in query:
        return "Shutting down. Goodbye!"
    elif "remember" in query:
        # Simple memory example
        parts = query.split("remember")
        if len(parts) > 1:
            key_value = parts[1].strip()
            if ":" in key_value:
                key, value = key_value.split(":", 1)
                memory[key.strip()] = value.strip()
                save_memory(memory)
                return f"Remembered: {key} is {value}"
        return "What should I remember?"
    elif "recall" in query:
        parts = query.split("recall")
        if len(parts) > 1:
            key = parts[1].strip()
            if key in memory:
                return f"{key} is {memory[key]}"
            else:
                return f"I don't remember {key}"
    else:
        return "I'm sorry, I didn't understand that. Can you please repeat?"
