import speech_recognition as sr
import pyttsx3
import json
import os
from voice import listen, speak
from nlp import process_query
from control import execute_command
from memory import load_memory, save_memory

def main():
    engine = pyttsx3.init()
    recognizer = sr.Recognizer()
    memory = load_memory()

    speak("Hello, I am JATAYU, your AI assistant. How can I help you today?")

    while True:
        try:
            query = listen(recognizer)
            if query:
                print(f"You said: {query}")
                response = process_query(query, memory)
                speak(response)
                if "shutdown" in query.lower():
                    break
        except Exception as e:
            print(f"Error: {e}")
            speak("Sorry, I didn't catch that.")

    save_memory(memory)
    speak("Goodbye!")

if __name__ == "__main__":
    main()
