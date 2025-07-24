from flask import Flask, render_template
# Import all check functions
from security_checker import (
    check_s3_buckets, 
    check_root_mfa, 
    check_old_access_keys, 
    check_risky_security_groups,
    check_iam_users_mfa  # <-- Import the new function
)

app = Flask(__name__)

@app.route('/')
@app.route('/')
def dashboard():
    # Run all checks
    all_issues = (
        check_s3_buckets() +
        check_root_mfa() +
        check_old_access_keys() +
        check_risky_security_groups() +
        check_iam_users_mfa()
    )
    
    # --- ADD THIS LOGIC TO COUNT SEVERITIES ---
    counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Info': 0
    }
    for issue in all_issues:
        if issue['severity'] in counts:
            counts[issue['severity']] += 1
            
    # Pass both issues and counts to the template
    return render_template('index.html', issues=all_issues, counts=counts)

if __name__ == '__main__':
    app.run(debug=True)