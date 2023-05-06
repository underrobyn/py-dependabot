import logging
from time import sleep, time
from json import loads
from requests import Session, sessions
from requests.exceptions import ConnectionError

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
				dismisser {
					login
					name
				}
				fixedAt
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
					firstPatchedVersion {
						identifier
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
				vulnerableRequirements
			}
		}
	}
}
"""


class GitHubGraphQLClient:

	RETRY_INTERVAL: int = 5
	GRAPHQL_ENDPOINT: str = 'https://api.github.com/graphql'
	_s: sessions.Session

	_rate_limit: dict = {
		'limit': 50000,
		'remaining': 50000,
		'reset': 0
	}

	def __init__(self, token: str) -> None:
		self._s = Session()

		self._s.headers.update({
			'Authorization': f'bearer {token}'
		})

	def _internal_query(self, query: str) -> dict:
		try:
			resp = self._s.post(url=self.GRAPHQL_ENDPOINT, json={'query': query})
		except ConnectionError as err:
			logging.error('There was a connection error... Retrying in 3 seconds')
			logging.error(err.strerror)

			sleep(self.RETRY_INTERVAL)
			return self._internal_query(query)

		self._rate_limit['limit'] = int(resp.headers['X-RateLimit-Limit'])
		self._rate_limit['remaining'] = int(resp.headers['X-RateLimit-Remaining'])
		self._rate_limit['reset'] = int(resp.headers['X-RateLimit-Reset'])

		logging.debug(f'RateLimit: {self._rate_limit["remaining"]} / {self._rate_limit["reset"]}')

		if self._rate_limit['remaining'] == 0:
			reset_time = self._rate_limit['reset'] - int(time())
			logging.warning('Rate limit reached, waiting for reset in {reset_time} seconds')
			sleep(reset_time)
			return self._internal_query(query)

		if resp.status_code == 200:
			return loads(resp.text)

		sleep(self.RETRY_INTERVAL)
		return self._internal_query(query)

	def query(self, query: str) -> dict:
		response = self._internal_query(query)

		if 'errors' in response:
			logging.error(f'{response["errors"]}')
			raise RuntimeError('GraphQL API error')

		if 'data' not in response:
			logging.error(response)
			raise RuntimeError('Request failed')

		return response
