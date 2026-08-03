import psutil
import time

# single-user test (kept for reference / development process)
# user = {
#     "name": "Emmanuel",
#     "department": "IT",
#     "role": "IT Admin",
#     "trust_score": 95,
#     "clearance_level": 5
# }
# print(user)
# result = check_access(user)
# print(result)


def check_access(user):
    if user["department"] == "IT" and user["clearance_level"] >=3 and user["trust_score"] > 70:
        return True
    elif user["role"] == "IT Admin" and user["department"] == "IT" and user["clearance_level"] >= 5 and user["trust_score"] > 80:
        return True
    else:
        return False

users = [
    
    {"name" : "Emmanuel", "department" : "IT", "role" : "Manager", "trust_score" : 80, "clearance_level" : 4},
    {"name" : "John", "department" : "HR", "role" : "Staff", "trust_score" : 65, "clearance_level" : 3},
    {"name" : "Alex", "department" : "Operations", "role" : "staff", "trust_score" : 40, "clearance_level" : 2},
    {"name" : "Billy", "department" : "Finance", "role" : "Manager", "trust_score" : 69, "clearance_level" : 3},
    {"name" : "Lisa", "department" : "IT", "role" : "IT Admin", "trust_score" : 65, "clearance_level" : 4}
]

  #In order for me to add log files to this, I have to change the syntax from only this (below) to this (below x2):
    #  for user in users:

    #result = check_access(user)
    #if result== True: 
    
      #  print(f"Hey {user["name"]}, you've been granted access!")

    
    #else:
     #   print(f"{user["name"]} - Access: Denied") 

class Trustengine:
    def __init__(self, full_threshold=70, monitor_threshold=40):
        self.full_threshold = full_threshold
        self.monitor_threshold = monitor_threshold

    #The base of ZTA

    def evaluate(self, user): 
        qualifies = False
        if user["department"] == "IT" and user["clearance_level"] >=3 or user["role"] == "IT Admin" and user["department"] == "IT" and user["clearance_level"] >=5:
            qualifies = True
    
        if qualifies == False:
            return "Role mismatch - Blocked"
        
        
        elif qualifies == True:
            if user["trust_score"] >= self.full_threshold:
                return "Full access granted!"
            elif user["trust_score"] >= self.monitor_threshold:
                return "Monitored -- Restricted access"
            else:
                return "Blocked, your trust score is too low"
           # put comment  
   
engine = Trustengine()
       
for user in users:

    result = engine.evaluate(user)
    
    
    print(f"{user['name']} : {result}")
    with open("access_log.txt", "a") as log_file:
        log_file.write(f"{user['name']} - {result}\n")
    
    
# comment this as well






#print("want to test your own scenario?")

#choice = input("yes or no? ")


#if choice.lower() == "yes":
    #print("starting scenario")

#else: 
    #print("No worries, thanks for testing the demo")


def log_event(message):
    # Writes a timestamped line to decision_log.txt so external tools (like Wazuh)
    # can monitor real access decisions made by the ZTA engine.
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("decision_log.txt", "a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")

class PEP:
    def __init__(self, policy_administrator, policy_engine, resources):
        self.policy_administrator = policy_administrator
        self.policy_engine = policy_engine
        self.resources = resources

    def accept_resource(self, user_id, password, resource_name):
        user_id = user_id.lower()
        resource_name = resource_name.lower()
        resource = self.resources[resource_name]

        if self.policy_administrator.has_active_session(user_id):
            self.enforce_decision("granted", resource, user_id)
        else:
            user = self.policy_administrator.verify_credentials(user_id,password)

            if user is None:
                self.enforce_decision("blocked", resource, user_id)
            else:
                self.policy_administrator.establish_session(user_id)
                decision = self.policy_engine.evaluate(user, resource)
                self.enforce_decision(decision, resource, user_id)

    def enforce_decision(self, decision, resource, user_id):
        # "blocked" bug fix: PolicyEngine returns messages like "Role mismatch - Blocked"
        # or "Blocked, your trust score is too low", not the literal word "blocked".
        # Checking for the substring (case-insensitive) catches all of these correctly.
        if "blocked" in decision.lower():
            resource.deny_access()
            log_event(f"user={user_id} resource={resource.resource_name} decision=DENIED ({decision})")
        else:
            resource.grant_access()
            log_event(f"user={user_id} resource={resource.resource_name} decision=GRANTED ({decision})")

class PolicyAdministrator:
    def __init__(self, active_sessions, session_log, user_directory):
        self.active_sessions = active_sessions
        self.session_log = session_log
        self.user_directory = user_directory
        self.failed_attempts = {}
        self.locked_accounts = {}

    def has_active_session(self, user_id):
        return user_id in self.active_sessions

    def verify_credentials(self, user_id, password):
        if user_id in self.locked_accounts:
            print(f"ACCOUNT LOCKED - {user_id} has too many failed attempts")
            log_event(f"user={user_id} decision=LOCKOUT_BLOCKED (account already locked)")
            return None

        user = self.user_directory.get(user_id)
        if user is None:
            return None

        if password == user.credentials:
            self.failed_attempts[user_id] = 0
            return user
        else:
         if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = 0
        self.failed_attempts[user_id] = self.failed_attempts[user_id] + 1

        if self.failed_attempts[user_id] >= 3:
            self.locked_accounts[user_id] = True
            print(f"ACCOUNT LOCKED - {user_id} after {self.failed_attempts[user_id]} failed attempts")
            log_event(f"user={user_id} decision=ACCOUNT_LOCKED (after {self.failed_attempts[user_id]} failed attempts)")

        return None

    def establish_session(self, user_id):
        self.active_sessions[user_id] = True

    def terminate_session(self,user_id):
        del self.active_sessions[user_id]

class PolicyEngine:
    def __init__(self, full_threshold=70, monitor_threshold=40):
        self.full_threshold = full_threshold
        self.monitor_threshold = monitor_threshold

    def evaluate(self, user, resource):
        qualifies = False
        if resource.required_department == "All" or user.department == resource.required_department:
            if user.clearance_level >= resource.required_clearance_level:
                qualifies = True

        if qualifies == False:
            return "Role mismatch - Blocked"
        else:
            if user.trust_score >= self.full_threshold:
                return "Full access granted!"
            elif user.trust_score >= self.monitor_threshold:
                return "Monitored -- Restricted access"
            else:
                return "Blocked, your trust score is too low"



class User:
    def __init__(self, user_id, name, clearance_level, trust_score, department, role, credentials):
        self.user_id = user_id
        self.name = name
        self.clearance_level = clearance_level
        self.trust_score = trust_score
        self.department = department
        self.role = role
        self.credentials = credentials

class Resource:
    def __init__(self, resource_name, required_department, required_clearance_level):
        self.resource_name = resource_name
        self.required_department = required_department
        self.required_clearance_level = required_clearance_level
    def grant_access(self):
        print(f"Access GRANTED for {self.resource_name}")

    def deny_access(self):
        print(f"Access DENIED for {self.resource_name}")

resources = {
    "teams": Resource("Teams", "All", 1),
    "payroll": Resource("Payroll", "Finance", 3),
    "employee_data" : Resource("Employee_data", "HR", 3),
    "inventory": Resource("Inventory", "Operations", 2)
}

users_directory = {
    "a001": User("A001", "Emmanuel Phil", 4, 80, "IT", "Manager", "pass123"),
    "a002": User("A002", "Lisa Mendez", 4, 65, "IT", "IT Admin", "pass456"),
    "a003": User("A003", "Sarah Chen", 3, 75, "Finance", "Manager", "pass789"),
    "a004": User("A004", "John Stark", 2, 60, "Finance", "Staff", "pass123"),
    "a005": User("A005", "Alex Pool", 4, 80, "HR", "Manager", "pass456"),
    "a006": User("A006", "Billy Moon", 5, 83, "Finance", "Admin", "pass789")
}

policy_administrator = PolicyAdministrator({}, "session_log.txt", users_directory)
policy_engine = PolicyEngine()
pep = PEP(policy_administrator, policy_engine, resources)

#Here, I am running a test to call on resources from the user, it goes 
pep.accept_resource("A003", "pass789", "Payroll")
#pep.accept_resource("A004", "Poop129", "Employee_data")

print("want to test your own scenario?")
choice = input("yes or no?")

if choice.lower() == "yes":
    user_id = input("Enter your user ID")
    password = input("Enter your password")
    resource_name = input("Enter the resource you want to access")
    pep.accept_resource(user_id, password, resource_name)
else: 
    print("That's fine, thanks for testing the demo")




process = psutil.Process()
process.cpu_percent(interval=None)

start_time = time.time()
for i in range(1700):
    pep.accept_resource("a001", "pass123", "teams")
end_time = time.time()

cpu_usage = process.cpu_percent(interval=None)
print(f"CPU usage over 1700 requests: {cpu_usage}%")
print(f"Total time for 1700 requests: {end_time - start_time:.4f} seconds")



process.cpu_percent(interval=None)

start_time = time.time()
for i in range(1700):
    pep.accept_resource("a001", "pass123", "teams")
    time.sleep(0.1)
end_time = time.time()

cpu_usage_steady = process.cpu_percent(interval=None)
print(f"Steady-state CPU usage over 1700 spaced-out requests: {cpu_usage_steady}%")
print(f"Total time for 1700 spaced-out requests: {end_time - start_time:.4f} seconds")

pep.accept_resource("a004", "wrongpass", "teams")
pep.accept_resource("a004", "wrongpass", "teams")
pep.accept_resource("a004", "wrongpass", "teams")