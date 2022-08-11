from github import Github
from dotenv import load_dotenv

from os import getenv
from graphql import github_graphql_query, GRAPHQL_BASE_DEPENDABOT_QUERY, GRAPHQL_API_ENDPOINT


class DependabotRepo(object):

	def __init__(self, org, repo):
		super().__init__()
		self._org = org
		self._repo = repo

		self.full_name = self._repo.full_name
		self.name = self._repo.name

		self._nodes = []
		self.security_events = []
		self.security_event_count = 0
		self.security_event_critical = 0
		self.security_event_high = 0
		self.security_event_moderate = 0
		self.security_event_low = 0

		self.issues = []

	def __get_graphql_query(self):
		return GRAPHQL_BASE_DEPENDABOT_QUERY.replace('{{owner}}', self._org).replace('{{repo}}', self._repo.name)

	def __get_security_events(self):
		return github_graphql_query(
			GRAPHQL_API_ENDPOINT,
			getenv('GITHUB_TOKEN'),
			self.__get_graphql_query()
		)

	def get_security_events(self):
		data = self.__get_security_events()

		if 'data' not in data:
			raise RuntimeError('Request failed')

		if 'repository' in data['data']:
			self._nodes = data['data']['repository']['vulnerabilityAlerts']['nodes']

		if len(self._nodes) > 0:
			self.__parse_security_events()

	def __parse_security_events(self):
		for node in self._nodes:
			self.security_event_count += 1

			if node['securityVulnerability']['severity'] == 'CRITICAL':
				self.security_event_critical += 1
			elif node['securityVulnerability']['severity'] == 'HIGH':
				self.security_event_high += 1
			elif node['securityVulnerability']['severity'] == 'MODERATE':
				self.security_event_moderate += 1
			elif node['securityVulnerability']['severity'] == 'LOW':
				self.security_event_low += 1
			else:
				raise RuntimeError('Unknown node[securityVulnerability][severity]')

			self.security_events.append({
				'created_at': node['createdAt'],
				'dismissed_at': node['dismissedAt'],
				'manifest_path': node['vulnerableManifestPath'],
				'manifest_filename': node['vulnerableManifestFilename'],
				'name': node['securityVulnerability']['package']['name'],
				'description': node['securityVulnerability']['advisory']['description'].strip().replace('\n', ''),
				'severity': node['securityVulnerability']['severity'],
				'vulnerableRange': node['securityVulnerability']['vulnerableVersionRange']
			})


if __name__ == '__main__':
	load_dotenv()
	g = Github(getenv('GITHUB_TOKEN'))
	org = g.get_organization(getenv('GITHUB_ORG_NAME'))

	dr = DependabotRepo(getenv('GITHUB_ORG_NAME'), org.get_repo('test-repo-name'))
	dr.get_security_events()
	print(dr.name)
	print(dr.security_events)
	print(f'{dr.security_event_count=},\n{dr.security_event_critical=},\n{dr.security_event_high=},\n{dr.security_event_moderate=},\n{dr.security_event_low=}')
    