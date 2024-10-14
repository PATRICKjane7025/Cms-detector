from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Your WhatCMS API key
WHATCMS_API_KEY = 'w2q163y5115eir0mewb87be7rqa6rza0jbkhz6o5z4gr9p9je5ucgy3z4atrot4h03xx60'

# Function to detect CMS using WhatCMS API
def detect_cms(url):
    api_url = f"https://whatcms.org/APIEndpoint/Detect?key={WHATCMS_API_KEY}&url={url}"
    try:
        response = requests.get(api_url)
        print(f"API response status: {response.status_code}")
        print(f"API response data: {response.text}")
        if response.status_code == 200:
            data = response.json()
            if data['result']['code'] == 200:
                cms_name = data['result']['name']
                version = data['result'].get('version', 'Unknown')
                return cms_name, version
            else:
                print(f"Error in WhatCMS API response: {data['result']['msg']}")
        else:
            print(f"Failed to fetch CMS data. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error connecting to WhatCMS API: {e}")
    return None, None

def construct_cpe(cms_name, version):
    cpe_vendor = {
        'wordpress': 'wordpress',
        'joomla': 'joomla',
        'drupal': 'drupal',
    }
    cpe_product = {
        'wordpress': 'wordpress',
        'joomla': 'joomla_cms',
        'drupal': 'drupal',
    }
    if cms_name.lower() in cpe_vendor:
        vendor = cpe_vendor[cms_name.lower()]
        product = cpe_product[cms_name.lower()]
        cpe_string = f"{vendor}:{product}:{version}"
        return cpe_string
    else:
        return None

def convert_cms_name_to_lowercase(cms_name):
    return cms_name.lower()

def get_cves_from_nvd(cms_name, version):
    cpe_string = construct_cpe(cms_name, version)
    if not cpe_string:
        return [f"Unsupported CMS: {cms_name}. No CPE available."]
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:{convert_cms_name_to_lowercase(cms_name)}:{convert_cms_name_to_lowercase(cms_name)}:{version}"
    print(f"NVD API URL: {nvd_url}")
    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        if not response.text:
            return ["No data returned from NVD API"]
        try:
            cve_data = response.json()
        except ValueError as e:
            return [f"Error parsing JSON response from NVD API: {str(e)}"]
        cve_items = cve_data.get('vulnerabilities', [])
        map={}
        for cve in cve_items:
            cve_description = cve.get('cve', {}).get('descriptions', [{}])[0].get('value', '')
            cve_ID = cve.get('cve', {}).get('id', '')
            map [cve_ID]=cve_description
            

    
        if not map:
            return ["No CVEs found for this CMS version."]
        return map
    except requests.RequestException as e:
        return [f"Error fetching data from NVD API: {str(e)}"]

# Main route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        cms_name, version = detect_cms(url)
        if cms_name:
            cve_list_with_descriptions = get_cves_from_nvd(cms_name, version)
            return render_template('index.html', url=url, cms_name=cms_name, version=version, cve_list=cve_list_with_descriptions)
        else:
            cms_name, version, cve_list_with_descriptions = "Unknown", "Unknown", ["Could not detect CMS or version."]
            return render_template('index.html', url=url, cms_name=cms_name, version=version, cve_list=cve_list_with_descriptions)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)