from requests import post
from time import sleep
from json import loads


GRAPHQL_API_ENDPOINT = 'https://api.github.com/graphql'

GRAPHQL_BASE_DEPENDABOT_QUERY = """
query dependabotEvents($owner: String = "{{owner}}", $repo: String = "{{repo}}", $num: Int = 100) {
	repository(owner: $owner, name: $repo) {
		vulnerabilityAlerts(first: $num) {
			nodes {
				createdAt
				dismissedAt
				securityVulnerability {
					advisory {
						description
					}
					package {
						name
					}
					severity
					vulnerableVersionRange
				}
				vulnerableManifestPath
				vulnerableManifestFilename
			}
		}
	}
}
"""


def github_graphql_query(url, token, query):
	r = post(url, headers={
		'Authorization': f'bearer {token}'
	}, json={'query': query})

	if r.status_code == 200:
		return loads(r.text)

    # Sleep to avoid API limits being reached
	sleep(3)
    
	return github_graphql_query(url, token, query)
