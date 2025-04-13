import time
from utils.Enums import Action



class NodeInputHandler:
    def __init__(self, node, spoof_flag, firewall_flag):
        self.node = node
        self.spoof_flag = spoof_flag
        self.firewall_flag = firewall_flag
        self.menu_actions = {
            '1': {"msg": "Ping", "action":self.ping},
            '2': {"msg": "Send a Message", "action":self.send_message},
            '3': {"msg": "Exit Program", "action": self.exit_program}
        }
        self.firewall_actions = {
            "1": "Add an IP rule",
            "2": "Add a Network rule",
            "3": "Remove a rule",
            "4": "List current rules",
            "5": "Return to main menu",
        }

        self.rule_actions = {
            "1": {"msg": "Allow", "action": Action.ALLOW},
            "2": {"msg": "Block", "action": Action.BLOCK}
        }

        self.ping_actions = {
            '1': 'Ping once',
            '2': 'Ping on loop',
            '3': 'Return to main menu'
        }

        if self.firewall_flag:
            self.menu_actions['4'] = self.menu_actions['3']
            self.menu_actions['3'] = {
                "msg": "Manage Firewall Rules", 
                "action": self.manage_firewall
            }

    def run(self):
        print()
        while True:
            print("Enter the corresponding number:")
            for key, value in self.menu_actions.items():
                print(f"{key}. {value['msg']}")

            menu_action = input("Input your choice below: \n").strip()

            if menu_action in self.menu_actions:
                self.menu_actions[menu_action][
                    "action"
                ]()  # Call the corresponding method
            else:
                print("Invalid option. Please enter a valid number.\n")
    
    def ping(self):
        icmp_ip = input("Enter an IP to ping: ")
        print("Enter the corresponding number:")
        for key, value in self.ping_actions.items():
            print(f"{key}. {value}")
        ping_action = input("Input your choice below: \n").strip()
        if ping_action in self.ping_actions:
            if ping_action == "1":
                self.node.send_icmp_request(icmp_ip)
            elif ping_action == "2":
                print("Press Ctrl+C to stop pinging.")
                try:
                    while True:
                        print("Sending ping...")
                        self.node.send_icmp_request(icmp_ip)
                        time.sleep(2)
                except KeyboardInterrupt:
                    print("Stopped pinging.")
                except Exception as e:
                    print(f"An error occurred: {e}")
            else:
                return
        else:
            print("Invalid option. Please enter a valid number.")

    def send_message(self):
        dest = input("Enter an IP to message: ").strip()
        msg = input("Enter message: ").strip()
        spoof_ip = ""
        if self.spoof_flag:
            spoof_ip = input("Enter IP address to spoof as: ").strip()
        self.node.send_TCP_data(dest, msg, spoof_ip)

    def manage_firewall(self):
        print("\nFirewall Management:")
        while True:
            self.node.firewall.display_rules()
            print("Enter the corresponding number:")
            for key, value in self.firewall_actions.items():
                print(f"{key}. {value}")

            firewall_action = input("Input your choice below: \n").strip()
            if firewall_action in self.firewall_actions:
                if firewall_action in ["1", "2"]:
                    src_prompt = "Enter source IP to allow/block: " if firewall_action == "1" else "Enter source Network to allow/block: "
                    src = input(src_prompt)
                    print("Enter the corresponding number:")
                    for key, value in self.rule_actions.items():
                        print(f"{key}. {value['msg']}")

                    rule_action = input("Input your choice below: \n").strip()
                    if rule_action in self.rule_actions:
                        action = self.rule_actions[rule_action]["action"] 
                    else:
                        print("Invalid option. Please enter a valid number.\n")
                        break
                    if firewall_action == "1":
                        self.node.firewall.add_ip_rule(src, action)
                    else:
                        self.node.firewall.add_network_rule(src, action)

                elif firewall_action == "3":
                    index = int(input("Enter the index of the rule to remove: "))
                    self.node.firewall.remove_rule_by_index(index)

                elif firewall_action == "4":
                    self.node.firewall.display_rules()

                else:
                    return

            else:
                print("Invalid option. Please enter a valid number.")

    def exit_program(self):
        print("Exiting program...")
        exit()
