import requests
from flask import Flask, request, send_file, request, session, jsonify, render_template, current_app, url_for, render_template

def idea_for_LATER():
    #store in a database for correlation across requests.
    import hashlib
    hash_id = hashlib.sha256(str(fingerprint).encode()).hexdigest()


app = Flask(__name__)

@app.route('/')
def index():
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'static':
            continue
        try:
            url = url_for(rule.endpoint, _external=True)
            methods = ','.join(sorted(m for m in rule.methods if m not in ['HEAD', 'OPTIONS']))
            routes.append({
                'url': url,
                'methods': methods,
                'endpoint': rule.endpoint
            })
        except Exception:
            pass  # skip routes that need params
    routes.sort(key=lambda x: x['url'])
    return render_template('index.html', routes=routes)

def check_headers(url):
    r = requests.get(url)
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    print("\nParsed CSP Directives:")
    csp = r.headers.get("Content-Security-Policy")
    if csp:
        for directive in csp.split(";"):
            print(" -", directive.strip())


@app.route('/whoami')
def whoami():
    return f"Your IP is: {request.remote_addr}"


@app.route('/inspect_header', methods=['GET'])
def inspect_header():
    headers = dict(request.headers)

    # Print to console
    #print("=== Incoming Headers ===")
    #for k, v in headers.items():
    #    print(f"{k}: {v}")

    # Return as JSON
    return jsonify({"headers": headers})


@app.route('/client_side_fingerprint')
def client_side_fingerprint():
    return render_template('client_side_fingerprint.html')

@app.route('/client_side_fingerprint_log', methods=['POST'])
def log():
    data = request.get_json() or {}
    visitor_id = data.get('visitorId')
    components = data.get('components', {})

    print("\n" + "="*60)
    print(f"VISITOR ID: {visitor_id}")
    print(f"IP: {request.remote_addr}")
    print(f"UA: {request.headers.get('User-Agent')}")
    print("-" * 60)

    # PRINT EVERYTHING FingerprintJS collected
    print("FINGERPRINT COMPONENTS:")
    for key, value in components.items():
        # Skip large blobs (like canvas, audio) to avoid spam
        if isinstance(value, dict):
            if 'value' in value:
                val = value['value']
                # Truncate long strings
                if isinstance(val, str) and len(val) > 100:
                    val = val[:100] + "..."
                print(f"  {key:25}: {val}")
            else:
                print(f"  {key:25}: {value}")
        else:
            print(f"  {key:25}: {value}")
    print("="*60 + "\n")

    return jsonify({"status": "ok"}), 200


@app.route('/tab-activity_tracker', methods=['GET', 'POST'])
def activity_tracker():
    if request.method == 'GET':
        return render_template('tab_activity.html')
    
    data = request.get_json() or {}
    event = data.get('event')
    visitor_id = data.get('visitorId', '')[:8]
    print(f"[{visitor_id}] {event}")
    return jsonify({"status": "ok"})


@app.route('/server_side_fingerprint', methods=['GET', 'POST'])
def server_side_fingerprint():
    fingerprint = {
        # Network identity
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "remote_addr": request.remote_addr,

        # Browser & device
        "user_agent": request.user_agent.string,
        "platform": request.user_agent.platform,
        "browser": request.user_agent.browser,
        "version": request.user_agent.version,
        "language": request.headers.get("Accept-Language"),
        "encoding": request.headers.get("Accept-Encoding"),
        "sec_ch_ua": request.headers.get("sec-ch-ua"),
        "sec_ch_ua_platform": request.headers.get("sec-ch-ua-platform"),
        "sec_ch_ua_mobile": request.headers.get("sec-ch-ua-mobile"),

        # Request context
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers),
        "cookies": request.cookies,
        "auth_header": request.headers.get("Authorization"),
        
        # Request headers
        "Request headers": dict(request.headers)
        
        
        # Application-level identity
        #"session_user": session.get("user_id"),
        #"form_user": request.form.get("username"),
        #"json_user": request.get_json(silent=True) or {}
    }

    print("SERVER-SIDE FINGERPRINT (Passive) i.e., User Fingerprint:", fingerprint)
    return jsonify({"status": "logged", "fingerprint": fingerprint})



if __name__ == '__main__':
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint:20s} {','.join(rule.methods):20s} {rule}")
    
    app.run()