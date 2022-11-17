import csv
import logging
from datetime import datetime
from github import Github, Organization
from dotenv import load_dotenv
from os import getenv
from dependabot_repo import DependabotRepo
from graphql import GitHubGraphQLClient


def main(events: list) -> None:
	totals_headers = ['REPO_NAME', 'TOTAL', 'HIGH', 'HIGH', 'MODERATE', 'LOW']
	totals_data = []
	for repo in events:
		tmp = repo.security_event_count
		tmp['REPO_NAME'] = repo
		totals_data.append(tmp)

	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_totals.csv', totals_headers, totals_data)

	detailed_headers = [
		'repo_name', 'repo_description', 'number', 'created_at', 'dismissed_at', 'manifest_path', 'manifest_filename',
		'name', 'description', 'severity', 'vulnerableRange'
	]
	detailed_data = []
	closed_data = []

	def get_data(alert: dict, repo: DependabotRepo) -> dict:
		tmp = alert
		tmp['repo_name'] = repo.name
		tmp['repo_description'] = repo.description
		return tmp

	for repo in events:
		for alert in repo.security_events:
			detailed_data.append(get_data(alert, repo))

		for alert in repo.closed_events:
			closed_data.append(get_data(alert, repo))

	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_details.csv', detailed_headers, detailed_data)
	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_closed.csv', detailed_headers, closed_data)


def get_repo_security_data(o: Organization, client: GitHubGraphQLClient) -> list:
	security_data = []
	i = 0

	logging.info('Loading organisation repository list')
	for r in o.get_repos():
		i += 1

		logging.info(f'[{i}] Loading instance for: {r.name}')

		dr = DependabotRepo(getenv('GITHUB_ORG_NAME'), r, client)
		dr.get_security_events()

		logging.info(f'\t{dr.security_event_count=}')

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
