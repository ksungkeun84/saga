"""
    Add some seed data into the running user's agent.
"""
import os
import json
from agents.config import UserConfig

from tools.calendar import LocalCalendarTool
from tools.email import LocalEmailClientTool
from saga.config import ROOT_DIR


def read_jsonl_data(path):
    data = []
    with open(path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data


def main(user_configs_path):
    PATH_WITH_SEED_DATA = os.path.join(os.path.dirname(ROOT_DIR), "data")
    for fpath in os.listdir(user_configs_path):
        config_path = os.path.join(user_configs_path, fpath)
        # Read user config
        config = UserConfig.load(config_path, drop_extra_fields=False)
        all_user_tools = []
        for agent in config.agents:
            all_user_tools.extend(agent.tools)
        
        # Get user details
        name = config.name
        email = config.email
        
        # Read data for these tools and add to the agent
        for tool in all_user_tools:
            if tool == "email":
                tool_obj = LocalEmailClientTool(user_name=name, user_email=email)
            elif tool == "calendar":
                tool_obj = LocalCalendarTool(user_name=name, user_email=email)
            else:
                raise NotImplementedError(f"Tool {tool} not implemented yet.")
            
            # Read relevant data from data/
            tool_obj.seed_data(read_jsonl_data(os.path.join(PATH_WITH_SEED_DATA, fpath.split(".yaml")[0], f"{tool}.jsonl")))


if __name__ == "__main__":
    main("user_configs")
