import os
import json

class MLChatEngine:
    def __init__(self):
        self.system_instruction = ""
        self._initialize_system_instruction()

    def _initialize_system_instruction(self):
        """Load static knowledge base and format as system instruction"""
        knowledge_base = []
        
        # Path to the data file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(current_dir, 'data', 'chatbot_knowledge.json')
        
        try:
            if os.path.exists(data_path):
                with open(data_path, 'r', encoding='utf-8') as f:
                    knowledge_base = json.load(f)
        except Exception as e:
            print(f"Error loading chatbot knowledge base: {e}")

        # Format knowledge base as instructions
        kb_text = "You are a JavaScript Security Assistant. Use the following knowledge base to answer questions:\n\n"
        for item in knowledge_base:
            kb_text += f"Q: {item['question']}\nA: {item['answer']}\nKeywords: {item.get('keywords', '')}\n\n"
            
        self.system_instruction = kb_text + "\nIf the user asks about specific analysis results, refer to the provided context."

    def get_system_instruction(self):
        return self.system_instruction


