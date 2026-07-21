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
    
    
    print(f"{user["name"]} : {result}")
    with open("access_log.txt", "a") as log_file: 
            log_file.write(f"{user["name"]} - {result}\n")
    
    
# comment this as well






#print("want to test your own scenario?")

#choice = input("yes or no? ")


#if choice.lower() == "yes":
    #print("starting scenario")

#else: 
    #print("No worries, thanks for testing the demo")