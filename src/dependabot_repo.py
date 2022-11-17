import logging
from github import Github
from dotenv import load_dotenv
from os import getenv
from graphql import GRAPHQL_BASE_DEPENDABOT_QUERY, GitHubGraphQLClient


class DependabotRepo(object):

	def __init__(self, org, repo, client: GitHubGraphQLClient):
		super().__init__()
		self._org = org
		self._repo = repo
		self._client = client

		self.full_name = self._repo.full_name
		self.name = self._repo.name
		self.description = self._repo.description

		self._nodes = []
		self.security_events = []
		self.closed_events = []
		self.security_event_count = {
			'TOTAL': 0,
			'CRITICAL': 0,
			'HIGH': 0,
			'MODERATE': 0,
			'LOW': 0
		}

		self.issues = []

	def __get_graphql_query(self, after: str) -> str:
		return GRAPHQL_BASE_DEPENDABOT_QUERY\
			.replace('{{owner}}', self._org)\
			.replace('{{repo}}', self._repo.name)\
			.replace('{{after}}', after)

	def __get_security_events(self, after: str) -> dict:
		return self._client.query(self.__get_graphql_query(after))

	def __get_security_nodes(self, nodes: list, after: str) -> list:
		data = self.__get_security_events(after)

		if 'repository' in data['data']:
			vuln_alerts = data['data']['repository']['vulnerabilityAlerts']
			nodes = nodes + vuln_alerts['nodes']

			if vuln_alerts['pageInfo']['hasNextPage']:
				logging.info(f"Found another page with cursorID: {vuln_alerts['pageInfo']['endCursor']}")
				return self.__get_security_nodes(nodes, f", after: \"{vuln_alerts['pageInfo']['endCursor']}\"")

		return nodes

	def get_security_events(self):
		self._nodes = self.__get_security_nodes([], '')

		if len(self._nodes) > 0:
			self.__parse_security_events()

	def __parse_security_events(self):
		for node in self._nodes:
			alert = {
				'created_at': node['createdAt'],
				'dismissed_at': node['dismissedAt'],
				'dismissed_comment': node['dismissComment'],
				'dismissed_reason': node['dismissReason'],
				'number': node['number'],
				'manifest_path': node['vulnerableManifestPath'],
				'manifest_filename': node['vulnerableManifestFilename'],
				'name': node['securityVulnerability']['package']['name'],
				'description': node['securityVulnerability']['advisory']['description'].strip().replace('\n', ''),
				'severity': node['securityVulnerability']['severity'],
				'vulnerableRange': node['securityVulnerability']['vulnerableVersionRange']
			}

			# Only add to count if is active alert
			if node['state'] == 'OPEN':
				self.security_event_count['TOTAL'] += 1
				self.security_event_count[node['securityVulnerability']['severity']] += 1

				self.security_events.append(alert)
			else:
				self.closed_events.append(alert)


if __name__ == '__main__':
	load_dotenv()
	g = Github(getenv('GITHUB_TOKEN'))
	org = g.get_organization(getenv('GITHUB_ORG_NAME'))

	dr = DependabotRepo(getenv('GITHUB_ORG_NAME'), org.get_repo('test-repo-name'))
	dr.get_security_events()
	print(dr.name)
	print(dr.security_events)
	print(dr.closed_events)
	print(f'{dr.security_event_count=}')
