"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Server, CheckCircle, XCircle, Clock, Activity, FileText } from "lucide-react"

export function Dashboard() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">대시보드</h1>
        <Badge variant="outline" className="text-green-600 border-green-600">
          <Activity className="w-3 h-3 mr-1" />
          시스템 정상
        </Badge>
      </div>

      {/* 통계 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">총 호스트</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24</div>
            <p className="text-xs text-muted-foreground">+2 지난 주 대비</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">활성 플레이북</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <p className="text-xs text-muted-foreground">+1 이번 달</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">성공한 작업</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">156</div>
            <p className="text-xs text-muted-foreground">지난 24시간</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">실패한 작업</CardTitle>
            <XCircle className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">3</div>
            <p className="text-xs text-muted-foreground">지난 24시간</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 최근 작업 */}
        <Card>
          <CardHeader>
            <CardTitle>최근 작업</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { name: "웹서버 배포", status: "성공", time: "5분 전", host: "web-01" },
              { name: "데이터베이스 백업", status: "성공", time: "15분 전", host: "db-01" },
              { name: "시스템 업데이트", status: "실행중", time: "30분 전", host: "app-02" },
              { name: "로그 정리", status: "실패", time: "1시간 전", host: "log-01" },
            ].map((job, index) => (
              <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center space-x-3">
                  {job.status === "성공" && <CheckCircle className="h-4 w-4 text-green-600" />}
                  {job.status === "실행중" && <Clock className="h-4 w-4 text-yellow-600" />}
                  {job.status === "실패" && <XCircle className="h-4 w-4 text-red-600" />}
                  <div>
                    <p className="font-medium">{job.name}</p>
                    <p className="text-sm text-muted-foreground">{job.host}</p>
                  </div>
                </div>
                <div className="text-right">
                  <Badge
                    variant={job.status === "성공" ? "default" : job.status === "실행중" ? "secondary" : "destructive"}
                  >
                    {job.status}
                  </Badge>
                  <p className="text-xs text-muted-foreground mt-1">{job.time}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* 시스템 상태 */}
        <Card>
          <CardHeader>
            <CardTitle>시스템 상태</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>CPU 사용률</span>
                <span>45%</span>
              </div>
              <Progress value={45} className="h-2" />
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>메모리 사용률</span>
                <span>68%</span>
              </div>
              <Progress value={68} className="h-2" />
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>디스크 사용률</span>
                <span>32%</span>
              </div>
              <Progress value={32} className="h-2" />
            </div>

            <div className="pt-4 space-y-2">
              <div className="flex items-center justify-between p-2 bg-green-50 rounded">
                <span className="text-sm">온라인 호스트</span>
                <span className="font-medium text-green-600">22/24</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-red-50 rounded">
                <span className="text-sm">오프라인 호스트</span>
                <span className="font-medium text-red-600">2/24</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
