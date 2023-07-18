import vt
import time
from itertools import cycle

# Read the IP addresses or domains from the text file
with open("url.txt", "r") as file:
    urls = file.read().splitlines()

# Read the API keys from the file
with open("api.txt", "r") as api_file:
    api_keys = api_file.read().splitlines()

# Create a cycle iterator for API keys
api_key_cycle = cycle(api_keys)

# Open the output file for writing malicious URLs
with open("malicious_url.txt", "w") as output_file:
    # Process each URL/IP address
    for url in urls:
        # Get the current API key
        current_api_key = next(api_key_cycle)

        try:
            print(f"Processing {url} with API key: {current_api_key}")

            # Initialize the VirusTotal client with the current API key
            client = vt.Client(current_api_key)

            # Get the URL ID or IP address
            url_id = vt.url_id(url)

            # Retrieve the URL analysis information
            url_info = client.get_object("/urls/{}".format(url_id))

            # Check if the URL is not found on VirusTotal
            if not url_info:
                print(f"No results found for {url} on VirusTotal")
                print()
                continue

            # Check if it is malicious
            value = url_info.last_analysis_stats.get("malicious", 0)
            if value > 1 or value == 1:
                print(f"{url} is malicious")
                output_file.write(url + "\n")  # Write the malicious URL to the output file
            else:
                print(f"{url} is not malicious")

            print("Number of malicious reports:", value)
            print()

            # Pause for 20 seconds
            time.sleep(20)

        except Exception as e:
            print(f"An error occurred for {url}: {str(e)}")
            print("Moving to the next URL...")
            print()
            continue

        finally:
            # Close the VirusTotal client
            if client:
                client.close()

print("Processing completed.")
