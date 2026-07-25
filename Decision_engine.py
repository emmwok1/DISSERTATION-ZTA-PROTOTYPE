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


class PEP: 
    def __init__(self, policy_administrator, policy_engine, resources):
        self.policy_administrator = policy_administrator
        self.policy_engine = policy_engine
        self.resources = resources

    def accept_resource(self, user_id, password, resource_name):
        resource = self.resources[resource_name]

        if self.policy_administrator.has_active_session(user_id):
            self.enforce_decision("granted",resource)
        else:
            user = self.policy_administrator.verify_credentials(user_id,password)

            if user is None:
                self.enforce_decision("blocked", resource)
            else:
                self.policy_administrator.establish_session(user_id)
                decision = self.policy_engine.evaluate(user, resource)
                self.enforce_decision(decision, resource)

    def enforce_decision(self, decision, resource):
        if decision == "blocked":
            resource.deny_access()
        else:
            resource.grant_access()

class PolicyAdministrator:
    def __init__(self, active_sessions, session_log, user_directory):
        self.active_sessions = active_sessions
        self.session_log = session_log
        self.user_directory = user_directory

    def has_active_session(self, user_id):
        return user_id in self.active_sessions

    def verify_credentials(self, user_id, password):
        # Expecting user_directory to be a dict mapping user_id -> user dict
        user = self.user_directory.get(user_id)
        if user is None:
            return None
       
        if password == user.credentials:
            return user 
        else:
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