from agent.safety_agent import SafetyAgent
from sentient_agent_framework import DefaultServer, Session

if __name__ == "__main__":
    agent = SafetyAgent(name="SafetyAgent") 
    server = DefaultServer(agent)     
    
    server.run()
