import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class MLChatEngine:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.model = None
        self.chat_session = None
        self.system_instruction = ""
        self.analysis_context = ""
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self._initialize_system_instruction()
            self._setup_model()
        else:
            print("Warning: GOOGLE_API_KEY not found. Chatbot will not function correctly.")

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

    def _setup_model(self):
        """Initialize Gemini model"""
        generation_config = {
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 8192,
        }
        
        self.model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            generation_config=generation_config,
            system_instruction=self.system_instruction
        )
        self.chat_session = self.model.start_chat(history=[])

    def update_context(self, analysis_results):
        """Update context with findings from the latest analysis"""
        if not analysis_results:
            self.analysis_context = "No analysis results available yet."
            return

        # Flatten findings
        findings = []
        if isinstance(analysis_results, list):
            for file_res in analysis_results:
                findings.extend(file_res.get('findings', []))
        elif isinstance(analysis_results, dict):
             findings.extend(analysis_results.get('findings', []))
             
        # Format findings for the model
        context = "Here are the latest analysis findings:\n"
        if not findings:
            context += "No security issues were found in the analyzed files.\n"
        else:
            for f in findings:
                desc = f.get('description', 'No description')
                ftype = f.get('type', 'Unknown')
                severity = f.get('severity', 'Unknown')
                context += f"- [{severity}] {ftype}: {desc}\n"
                
        self.analysis_context = context
        
        # Send context to chat session as a system message (simulated via user message)
        if self.chat_session:
             try:
                self.chat_session.send_message(f"System Update: {self.analysis_context}")
             except Exception as e:
                 print(f"Error updating context: {e}")

    def get_response(self, user_input):
        """Get response from Gemini"""
        if not self.model:
            return "Error: Chatbot is not properly configured. Please check the API key."
            
        try:
            response = self.chat_session.send_message(user_input)
            return response.text
        except Exception as e:
            return f"I encountered an error while processing your request: {str(e)}"

