"use client"

import { Bar } from "react-chartjs-2";
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip } from "chart.js";
ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

export function ChartTableAndBar({ rows }: { rows: any[] }) {
  if (!rows || rows.length === 0) return <div>데이터가 없습니다.</div>;

  // "결과" 필드 기준으로 합계 계산
  const goodSum = rows.filter(row => row["결과"] === "GOOD").length;
  const badSum = rows.filter(row => row["결과"] === "BAD").length;
  const naSum = rows.filter(row => row["결과"] === "N/A").length;

  const chartData = {
    labels: ["양호", "취약", "N/A"],
    datasets: [
      {
        label: "점검 항목별 결과 합계",
        data: [goodSum, badSum, naSum],
        backgroundColor: [
          "#22c55e", // 초록
          "#ef4444", // 빨강
          "#6b7280"  // 회색
        ],
        barThickness: 60,
        maxBarThickness: 80,
      },
    ],
  };
  const isAllZero = goodSum === 0 && badSum === 0 && naSum === 0;
  return (
    // 기존 py-8에 mt-8 추가로 위쪽 여백 강화
    <div className="space-y-10 max-w-2xl mx-auto px-2 py-8 mt-8">
      <div className="flex justify-center mb-8" style={{ minHeight: 220 }}>
        {isAllZero ? (
          <div className="text-center text-gray-400 py-12">차트로 표시할 데이터가 없습니다.</div>
        ) : (
          <div style={{ width: 420, maxWidth: "100%" }}>
            <Bar
              data={chartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                  x: { grid: { display: false } },
                  y: { beginAtZero: true, ticks: { stepSize: 1 } }
                },
              }}
              height={220}
            />
          </div>
        )}
      </div>
      <div className="overflow-x-auto">
        <h2 className="text-lg font-bold mb-4 text-gray-800">항목별 상세 결과</h2>
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          <table className="min-w-full text-sm border rounded-lg overflow-hidden bg-white">
            <thead>
              <tr>
                {Object.keys(rows[0] || {}).map(key => (
                  <th key={key} className="px-2 py-2 border-b bg-gray-100 text-gray-700 font-semibold">{key}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i} className="hover:bg-gray-50">
                  {Object.keys(row).map(key => {
                    let cell = row[key];
                    let cellClass = "px-2 py-2 border-b ";
                    // "결과" 셀에만 색상 적용
                    if (key === "결과") {
                      if (cell === "GOOD") cellClass += "bg-green-50 text-green-700 font-bold";
                      else if (cell === "BAD") cellClass += "bg-red-50 text-red-700 font-bold";
                      else if (cell === "N/A") cellClass += "bg-gray-100 text-gray-500 font-bold";
                    }
                    return (
                      <td key={key} className={cellClass}>{cell}</td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
