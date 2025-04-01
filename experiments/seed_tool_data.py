"""
    Add some seed data into the running user's agent.
    Delete any existing data in storage before refreshing data
"""
import os
import json
from agent_backend.config import UserConfig

from agent_backend.tools.calendar import LocalCalendarTool
from agent_backend.tools.email import LocalEmailClientTool
from saga.config import ROOT_DIR


def read_jsonl_data(path):
    data = []
    with open(path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data


def main(user_configs_path):
    PATH_WITH_SEED_DATA = os.path.join(os.path.dirname(ROOT_DIR), "experiments", "data")
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
            
            # Clear out existing data
            tool_obj._clear_data()

            # Read relevant data from data/
            jsonl_data = read_jsonl_data(os.path.join(PATH_WITH_SEED_DATA, fpath.split(".yaml")[0], f"{tool}.jsonl"))
            tool_obj.seed_data(jsonl_data)
    
    print("Cleared all users' tool-related data and seeded with provided data!")


if __name__ == "__main__":
    main("../user_configs")
