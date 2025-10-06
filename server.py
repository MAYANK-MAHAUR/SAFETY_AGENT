from agent.safety_agent import SafetyAgent
from sentient_agent_framework import DefaultServer

if __name__ == "__main__":
    agent = SafetyAgent(name="SafetyAgent")  # create instance with name
    server = DefaultServer(agent)            # pass the instance, do NOT call it
    server.run()
