from glob import glob
import sys
import pandas as pd


PANDAS_XLSX_OPTS = {
	'strings_to_formulas': False,
	'strings_to_urls': False
}


def handle_details_file(name: str) -> None:
	frame = pd.read_csv(name)

	def highlight_cells(val) -> str:
		if val not in ('LOW', 'MODERATE', 'HIGH', 'CRITICAL'):
			return ''

		bg_colour = '#c6efce'
		text_colour = '#007b2e'
		if val == 'MODERATE':
			bg_colour = '#ffeb9c'
			text_colour = '#9c5724'
		elif val == 'HIGH':
			bg_colour = '#ffc7ce'
			text_colour = '#9c0055'
		elif val == 'CRITICAL':
			bg_colour = '#ff0000'
			text_colour = '#fff'

		return f'background-color: {bg_colour}; color: {text_colour}'

	try:
		frame = frame.style.applymap(highlight_cells, subset=['severity'])
	except KeyError as err:
		print(err)
		sys.exit(0)

	with pd.ExcelWriter(f'_{name[:-3]}xlsx', engine='xlsxwriter', options=PANDAS_XLSX_OPTS) as writer:
		frame.to_excel(writer, sheet_name='DependabotData', index=False)


def main():
	pd.set_option('display.max_colwidth', 20)

	for file in glob('*.csv'):
		if '_details' in file or '_advi' in file:
			handle_details_file(file)


if __name__ == '__main__':
	main()
