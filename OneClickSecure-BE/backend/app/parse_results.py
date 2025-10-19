import re
import csv
import glob

for filename in glob.glob('collected_results/Results_*.txt'):
    results = {}
    with open(filename, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"※ (U-\d+) 결과 : (.+)", line)
            if m:
                code = m.group(1)
                result = m.group(2)
                results[code] = result
    host = filename.split('_')[-1].replace('.txt', '')
    with open(f'final_report_{host}.csv', 'w', newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['항목코드', '결과'])
        for code, result in results.items():
            writer.writerow([code, result])
