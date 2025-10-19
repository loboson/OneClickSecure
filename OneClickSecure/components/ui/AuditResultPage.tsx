"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ChartTableAndBar } from "@/components/ui/chart";
import { Server, User, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function AuditResultPage() {
  const params = useSearchParams();
  const hostId = params.get("id");
  const username = params.get("username");
  const hostName = params.get("name");
  const hostIp = params.get("ip");

  const [csvRows, setCsvRows] = useState<any[]>([]);
  const [csvLoading, setCsvLoading] = useState(false);
  const [csvError, setCsvError] = useState("");

  useEffect(() => {
    if (hostId && username) {
      setCsvLoading(true);
      setCsvError("");
      setCsvRows([]);
      fetch(`http://localhost:8000/api/download/${hostId}/${username}/json`)
        .then(res => {
          if (!res.ok) throw new Error("CSV 데이터를 불러올 수 없습니다.");
          return res.json();
        })
        .then(data => {
          console.log("[CSV JSON 응답]", data);
          if (Array.isArray(data.rows)) setCsvRows(data.rows);
          else if (Array.isArray(data)) setCsvRows(data);
          else setCsvError("CSV 데이터 형식 오류");
        })
        .catch(err => setCsvError(err.message))
        .finally(() => setCsvLoading(false));
    }
  }, [hostId, username]);

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="mb-8">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Server className="h-6 w-6 text-blue-600" />
          {hostName || "호스트"} 점검 상세 결과
        </h1>
        <div className="mt-2 flex flex-wrap gap-4 text-sm text-gray-700">
          <span className="flex items-center gap-1"><Server className="h-4 w-4 text-blue-600" />호스트: <b>{hostName}</b></span>
          <span className="flex items-center gap-1"><User className="h-4 w-4 text-blue-600" />ID: <b>{username}</b></span>
          <span className="flex items-center gap-1">IP: <b>{hostIp}</b></span>
          <span className="flex items-center gap-1"><Calendar className="h-4 w-4 text-blue-600" />{new Date().toLocaleString()}</span>
        </div>
      </div>
      {/* 여백 추가 */}
      <div className="bg-white rounded-lg shadow p-6 border mt-10">
        {csvLoading ? (
          <div className="flex items-center justify-center h-40 text-blue-600 font-semibold">차트 로딩 중...</div>
        ) : csvError ? (
          <div className="text-red-500 font-medium">{csvError}</div>
        ) : csvRows.length > 0 ? (
          <ChartTableAndBar rows={csvRows} />
        ) : null}
      </div>
      <div className="mt-8 flex justify-end">
        <Button variant="outline" onClick={() => window.history.back()}>돌아가기</Button>
      </div>
    </div>
  );
}
