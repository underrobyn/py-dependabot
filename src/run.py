import csv
import json
from datetime import datetime
from github import Github
from dotenv import load_dotenv
from os import getenv

from dependabot_repo import DependabotRepo


def get_repo_list(org):
	tmp_list = []
	i = 0

	for repo in org.get_repos():
		i += 1

		print(f'[{i}] Created instance for: {repo.name}')
		dr = DependabotRepo(getenv('GITHUB_ORG_NAME'), repo)

		print(f'Getting security data...')
		dr.get_security_events()
		print(f'\t{dr.security_event_count=}')

		if dr.security_event_count > 0:
			tmp_list.append(dr)

	return tmp_list


def write_output_json(data: dict):
	json_string = json.dumps(data, indent=4)

	with open('output.json') as f:
		f.write(json_string)


def write_output_csv_dict(name: str, headers: list, data: list[dict]) -> None:
	with open(name, 'w', newline='', encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=headers)

		writer.writeheader()
		for item in data:
			writer.writerow(item)


if __name__ == '__main__':
	load_dotenv()
	g = Github(getenv('GITHUB_TOKEN'))
	org = g.get_organization(getenv('GITHUB_ORG_NAME'))

	START_TIME = datetime.now()
	DATE_STRING = START_TIME.strftime('%Y-%m-%d')

	repo_list = get_repo_list(org)

	totals_headers = ['repo_name', 'total', 'critical', 'high', 'moderate', 'low']
	totals_data = []
	for repo in repo_list:
		totals_data.append({
			'repo_name': repo.name,
			'total': repo.security_event_count,
			'critical': repo.security_event_critical,
			'high': repo.security_event_high,
			'moderate': repo.security_event_moderate,
			'low': repo.security_event_low
		})

	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_totals.csv', totals_headers, totals_data)

	detailed_headers = ['repo_name', 'created_at', 'dismissed_at', 'manifest_path', 'manifest_filename', 'name',
					 'description', 'severity', 'vulnerableRange']
	detailed_data = []
	for repo in repo_list:
		for alert in repo.security_events:
			tmp_dict = alert
			tmp_dict['repo_name'] = repo.name
			detailed_data.append(tmp_dict)

	write_output_csv_dict(f'{getenv("GITHUB_ORG_NAME")}_{DATE_STRING}_details.csv', detailed_headers, detailed_data)
