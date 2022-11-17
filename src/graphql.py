import logging
import requests
from requests import Session, sessions
from time import sleep
from json import loads


GRAPHQL_BASE_DEPENDABOT_QUERY = """
query dependabotEvents($owner: String = "{{owner}}", $repo: String = "{{repo}}", $num: Int = 100) {
	repository(owner: $owner, name: $repo) {
		vulnerabilityAlerts(first: $num{{after}}) {
			pageInfo {
				hasNextPage
				endCursor
			}
			nodes {
				createdAt
				dismissedAt
				dismissComment
				dismissReason
				number
				securityVulnerability {
					advisory {
						description
						identifiers {
							value
							type
						}
						cvss {
							score
							vectorString
						}
					}
					package {
						name
					}
					severity
					vulnerableVersionRange
				}
				state
				vulnerableManifestPath
				vulnerableManifestFilename
			}
		}
	}
}
"""


class GitHubGraphQLClient:

	RETRY_INTERVAL: int = 5
	GRAPHQL_ENDPOINT: str = 'https://api.github.com/graphql'
	_s: sessions.Session

	def __init__(self, token: str) -> None:
		self._s = Session()

		self._s.headers.update({
			'Authorization': f'bearer {token}'
		})

	def _internal_query(self, query: str) -> dict:
		try:
			r = self._s.post(url=self.GRAPHQL_ENDPOINT, json={'query': query})
		except requests.exceptions.ConnectionError as e:
			logging.error('There was a connection error... Retrying in 3 seconds')
			logging.error(e.strerror)

			sleep(self.RETRY_INTERVAL)
			return self._internal_query(query)

		if r.status_code == 200:
			return loads(r.text)

		sleep(self.RETRY_INTERVAL)
		return self._internal_query(query)

	def query(self, query: str) -> dict:
		response = self._internal_query(query)

		if 'data' not in response:
			logging.error(response)
			raise RuntimeError('Request failed')

		if 'errors' in response:
			logging.error(f'{response["errors"]}')
			raise RuntimeError('GraphQL API error')

		return response
