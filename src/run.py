import csv
import logging
from datetime import datetime
from github import Github, Organization
from dotenv import load_dotenv
from os import getenv
from dependabot_repo import DependabotRepo
from graphql import GitHubGraphQLClient


# CSV file headers
totals_headers = [
	'REPO_NAME', 'REPO_DESCRIPTION', 'ALERTS_URL', 'TOTAL', 'CRITICAL', 'HIGH', 'MODERATE', 'LOW'
]

detailed_headers = [
	'repo_name', 'repo_description', 'number', 'created_at', 'dismissed_at', 'manifest_path', 'name', 'description',
	'cve', 'severity', 'vulnerableRange', 'cvss_score', 'cvss_vector', 'alert_url'
]

advisory_headers = [
	'cve', 'ghsa', 'severity', 'cvss_score', 'cvss_vector', 'repos_affected', 'package_name', 'advisory_url'
]


def main(events: list) -> None:
	totals_data = []
	detailed_data = []
	closed_data = []
	advisory_data = []

	advisory_details = {}
	cve_list = {}

	for repo in events:
		tmp = repo.security_event_count
		tmp['REPO_NAME'] = repo.name
		tmp['REPO_DESCRIPTION'] = repo.description
		tmp['ALERTS_URL'] = f'https://github.com/{repo.full_name}/security/dependabot'

		totals_data.append(tmp)

	for repo in events:
		for alert in repo.security_events:
			update_advisory_details(advisory_details, alert)
			update_cve_object(cve_list, alert)
			detailed_data.append(get_data(alert, repo))

		for alert in repo.closed_events:
			closed_data.append(get_data(alert, repo))

	for advisory_id in advisory_details:
		advisory = advisory_details[advisory_id]

		advisory_item = {
			'cve': advisory['cve'],
			'ghsa': advisory['ghsa'],
			'cvss_score': advisory['cvss_score'],
			'cvss_vector': advisory['cvss_vector'],
			'repos_affected': '?',
			'package_name': advisory['package_name'],
			'severity': advisory['severity'],
			'vulnerableRange': advisory['vulnerableRange']
		}
		if advisory['cve'] in cve_list:
			advisory_item['repos_affected'] = cve_list[advisory['cve']]

		advisory_data.append(advisory_item)

	logging.info(f'Found: {len(detailed_data)} alerts open')
	logging.info(f'Found: {len(closed_data)} alerts closed')
	logging.info(f'Found: {len(totals_data)} repositories with open alerts')
	logging.info(f'Found: {len(advisory_data)} unique advisories found')

	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_totals.csv', totals_headers, totals_data)
	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_details.csv', detailed_headers, detailed_data)
	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_advisories.csv', advisory_headers, advisory_data)
	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_closed.csv', detailed_headers, closed_data)


def update_advisory_details(advisories: dict, alert: dict) -> None:
	unique_name = f"{alert['cve']}__{alert['ghsa']}"

	# If we already have the CVE details, skip
	if unique_name in advisories:
		return

	advisories[unique_name] = {
		'cve': alert['cve'],
		'ghsa': alert['ghsa'],
		'cvss_score': alert['cvss_score'],
		'cvss_vector': alert['cvss_vector'],
		'package_name': alert['name'],
		'severity': alert['severity'],
		'vulnerableRange': alert['vulnerableRange']
	}


def update_cve_object(cve_list: dict, alert: dict) -> None:
	# If cve is new, set count to 1
	if alert['cve'] not in cve_list:
		cve_list[alert['cve']] = 1
	else:
		cve_list[alert['cve']] += 1


def get_data(alert: dict, repo: DependabotRepo) -> dict:
	tmp = alert
	tmp['repo_name'] = repo.name
	tmp['repo_description'] = repo.description
	tmp['alert_url'] = f'https://github.com/{repo.full_name}/security/dependabot/{alert["number"]}'
	return tmp


def get_repo_security_data(o: Organization, client: GitHubGraphQLClient) -> list:
	security_data = []
	i = 0

	logging.info('Loading organisation repository list')
	repo_buffer = o.get_repos()
	num_repos = repo_buffer.totalCount

	for repo in repo_buffer:
		i += 1

		if repo.archived:
			logging.info(f'[{i}/{num_repos}] Skipping archived repository: {repo.name}')
			continue
			
		logging.info(f'[{i}/{num_repos}] Querying security events for: {repo.name}')

		dr = DependabotRepo(getenv('GITHUB_ORG_NAME'), repo, client)
		dr.get_security_events()

		logging.debug(f'\t{dr.security_event_count=}')

		# Don't add repo to list if there are no security events
		if dr.security_event_count['TOTAL'] > 0:
			security_data.append(dr)

	if i == 0:
		logging.warning('Found no repositories in this organisation')

	if len(security_data) == 0:
		logging.warning('No security events found in organisation.')
		exit(1)

	return security_data


def write_output_csv_dict(name: str, headers: list, data: list[dict]) -> None:
	with open(name, 'w', newline='', encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')

		writer.writeheader()
		for item in data:
			writer.writerow(item)


if __name__ == '__main__':
	logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(asctime)s - %(message)s')
	load_dotenv()
	logging.info(f'Will run for org: {getenv("GITHUB_ORG_NAME")}')

	g = Github(getenv('GITHUB_TOKEN'))
	org = g.get_organization(getenv('GITHUB_ORG_NAME'))

	START_TIME = datetime.now()
	DATE_STRING = START_TIME.strftime('%Y-%m-%d')

	# TODO: Change program to loop through alerts instead of repo->alerts
	client = GitHubGraphQLClient(getenv('GITHUB_TOKEN'))
	data = get_repo_security_data(org, client)

	main(data)
