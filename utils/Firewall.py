from utils.Enums import Action, Mode


class Firewall:
    def __init__(self, mode=Mode.BLACKLIST):
        """
        Initialize the firewall with a mode ('whitelist' or 'blacklist').
        - Whitelist: Only allow packets from sources in the rules.
        - Blacklist: Block packets from sources in the rules.
        """
        self.rules = []  # List of rules (source IPs or networks)
        self.mode = mode  # Mode can be 'whitelist' or 'blacklist'
        separator = "*" * 50
        print(separator)
        print(f"Firewall is initialised as {self.mode.value}")
        print(separator)
        print()

    def add_ip_rule(self, ip, action):
        """
        Add a rule for a specific IP address with an action ('allow' or 'block').
        """
        if action not in [Action.ALLOW, Action.BLOCK]:
            print("Invalid action. Use 'allow' or 'block'.")
            return
        if len(ip) != 4:
            print("Invalid IP format, please try again.")
            return
        self.rules.insert(0, {"ip": ip, "action": action})
        print(f"Added IP rule: {ip} -> {action.value}")

    def add_network_rule(self, network, action):
        """
        Add a rule for a network with an action ('allow' or 'block').
        """
        if action not in [Action.ALLOW, Action.BLOCK]:
            print("Invalid action. Use 'allow' or 'block'.")
            return
        if len(network) != 3:
            print("Invalid Network format, please try again.")
            return
        self.rules.insert(0, {"network": network, "action": action})
        print(f"Added Network rule: {network} -> {action.value}")

    def remove_rule_by_index(self, index):
        if 0 <= index < len(self.rules):
            removed_rule = self.rules.pop(index)
            if 'ip' in removed_rule:
                print(f"Removed rule: {{'ip': '{removed_rule['ip']}', 'action': '{removed_rule['action'].value}'}}")    
            else:
                print(f"Removed rule: {{'network': '{removed_rule['network']}', 'action': '{removed_rule['action'].value}'}}")    
        else:
            print("Invalid index. No rule removed.")

    def check_packet(self, packet):
        # if blacklist: by default - allow all
        # if whitelist: by default - deny all
        """
        Check if a packet should be allowed or blocked based on rules.
        The first matching rule takes precedence.
        """
        for rule in self.rules:
            if "ip" in rule:
                if packet.src_ip == rule["ip"]:
                    if rule["action"] == Action.BLOCK:
                        return False  # Block the packet
                    elif rule["action"] == Action.ALLOW:
                        return True  # Allow the packet

            if "network" in rule:
                if packet.src_ip.startswith(rule["network"]):
                    if rule["action"] == Action.BLOCK:
                        return False  # Block the packet
                    elif rule["action"] == Action.ALLOW:
                        return True  # Allow the packet
        return self.mode == Mode.BLACKLIST  # allow all if blacklist, else reject all

    def display_rules(self):
        """
        Display the current firewall rules.
        """
        print("\nFirewall Rules:")
        if self.rules:
            for index, rule in enumerate(self.rules):
                action_value = rule['action'].value 
                if 'ip' in rule:
                    print(f"{index}: {{'ip': '{rule['ip']}', 'action': '{action_value}'}}")    
                else:
                    print(f"{index}: {{'network': '{rule['network']}', 'action': '{action_value}'}}")            
            print("\n")
        else:
            print("No rules currently.\n")
