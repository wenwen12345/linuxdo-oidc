import os
import dotenv
import yaml
dotenv.load_dotenv()
with open(os.getenv("config_path"), 'r+', encoding="utf-8") as f:
    config = yaml.safe_load(f.read())
    for channel in config["channel"]:
        if channel["name"] == "Gemini":
            print(channel["secret"])
            channel["secret"] = "\n".join([channel["secret"]] + ["aaa"])
            # write to file ai!