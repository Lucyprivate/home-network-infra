#!/usr/bin/ucode
import { readfile } from 'fs';

function fail(message) {
	warn(message + '\n');
	exit(1);
}

function snapshot(path) {
	let periods = readfile(path + '/periods');
	if (periods == null || !length(trim(periods)))
		fail('Missing statistics periods');
	let result = {};
	let entries = split(trim(periods), '\n');
	push(entries, 'live');
	for (let period in entries) {
		if (period != 'live' && !match(period, /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/))
			fail('Invalid statistics period');
		let raw = readfile(path + '/' + period + '.json');
		let value;
		try { value = json(raw); }
		catch (e) { fail('Unreadable statistics JSON'); }
		if (type(value) != 'object' || type(value.columns) != 'array' || type(value.data) != 'array')
			fail('Invalid statistics schema');
		let sum = {};
		for (let key in ['conns', 'rx_bytes', 'rx_pkts', 'tx_bytes', 'tx_pkts']) {
			let column = index(value.columns, key);
			if (column < 0)
				fail('Missing statistics counter');
			sum[key] = 0;
			for (let row in value.data) {
				let counter = row[column];
				if (type(counter) != 'int' || counter < 0)
					fail('Invalid statistics counter');
				sum[key] += counter;
			}
		}
		result[period] = sum;
	}
	return result;
}

if (length(ARGV) != 2)
	fail('Two snapshot paths are required');
let before = snapshot(ARGV[0]);
let after = snapshot(ARGV[1]);
for (let period, counters in before) {
	if (after[period] == null)
		fail('Statistics period disappeared after migration');
	for (let counter, count in counters)
		if (after[period][counter] < count)
			fail('Statistics totals decreased after migration');
}
printf('%J\n', { verified: true, periods: length(keys(before)) - 1, live_totals_non_decreasing: true, totals_non_decreasing: true });
