import re
def password_strength_checker(password):
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should include at least one uppercase letter.")
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Password should include at least one lowercase letter.")
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Password should include at least one number.")
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Password should include at least one special character.")
    common_patterns = ["123", "password", "qwerty", "abc"]
    if any(pattern in password.lower() for pattern in common_patterns):
        feedback.append("Password should not contain common patterns like '123', 'password', etc.")
    else:
        score += 1
    strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    password_strength = strength[score]
    return password_strength, feedback
password = input("Enter a password to check its strength: ")
strength, feedback = password_strength_checker(password)
print(f"Password Strength: {strength}")
for comment in feedback:
    print(f"- {comment}")
