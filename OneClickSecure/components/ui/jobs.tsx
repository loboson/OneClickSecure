"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Clock, Search, CheckCircle, XCircle, Eye, RotateCcw } from "lucide-react"

export function Jobs() {
  const [searchTerm, setSearchTerm] = useState("")

  const jobs = [
    {
      id: 1,
      name: "웹서버 배포",
      playbook: "deploy-webserver.yml",
      status: "성공",
      startTime: "2024-01-15 14:30:00",
      duration: "2분 15초",
      host: "web-01, web-02",
      user: "admin",
    },
    {
      id: 2,
      name: "데이터베이스 백업",
      playbook: "backup-database.yml",
      status: "성공",
      startTime: "2024-01-15 12:00:00",
      duration: "5분 30초",
      host: "db-01",
      user: "admin",
    },
    {
      id: 3,
      name: "시스템 업데이트",
      playbook: "system-update.yml",
      status: "실행중",
      startTime: "2024-01-15 13:45:00",
      duration: "진행중...",
      host: "app-01, app-02",
      user: "admin",
    },
    {
      id: 4,
      name: "로그 정리",
      playbook: "cleanup-logs.yml",
      status: "실패",
      startTime: "2024-01-15 11:15:00",
      duration: "1분 45초",
      host: "log-01",
      user: "admin",
    },
    {
      id: 5,
      name: "보안 설정",
      playbook: "security-config.yml",
      status: "성공",
      startTime: "2024-01-14 16:20:00",
      duration: "8분 12초",
      host: "web-01, web-02, app-01",
      user: "security",
    },
  ]

  const filteredJobs = jobs.filter(
    (job) =>
      job.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      job.playbook.toLowerCase().includes(searchTerm.toLowerCase()) ||
      job.host.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "성공":
        return <CheckCircle className="h-4 w-4 text-green-600" />
      case "실패":
        return <XCircle className="h-4 w-4 text-red-600" />
      case "실행중":
        return <Clock className="h-4 w-4 text-yellow-600" />
      default:
        return <Clock className="h-4 w-4 text-gray-600" />
    }
  }

  const getStatusVariant = (status: string) => {
    switch (status) {
      case "성공":
        return "default"
      case "실패":
        return "destructive"
      case "실행중":
        return "secondary"
      default:
        return "outline"
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">작업 히스토리</h1>
      </div>

      {/* 검색 */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
        <Input
          placeholder="작업 검색..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10"
        />
      </div>

      {/* 작업 목록 */}
      <Card>
        <CardHeader>
          <CardTitle>최근 작업</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredJobs.map((job) => (
              <div key={job.id} className="border rounded-lg p-4 hover:bg-gray-50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(job.status)}
                      <h3 className="font-medium text-lg">{job.name}</h3>
                      <Badge variant={getStatusVariant(job.status)}>{job.status}</Badge>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm text-muted-foreground">
                      <div>
                        <span className="font-medium">플레이북:</span>
                        <p className="font-mono">{job.playbook}</p>
                      </div>
                      <div>
                        <span className="font-medium">시작 시간:</span>
                        <p>{job.startTime}</p>
                      </div>
                      <div>
                        <span className="font-medium">소요 시간:</span>
                        <p>{job.duration}</p>
                      </div>
                      <div>
                        <span className="font-medium">실행자:</span>
                        <p>{job.user}</p>
                      </div>
                    </div>

                    <div className="text-sm">
                      <span className="font-medium text-muted-foreground">대상 호스트:</span>
                      <p className="mt-1">
                        {job.host.split(", ").map((host, index) => (
                          <Badge key={index} variant="outline" className="mr-1">
                            {host}
                          </Badge>
                        ))}
                      </p>
                    </div>
                  </div>

                  <div className="flex space-x-2 ml-4">
                    <Button size="sm" variant="outline">
                      <Eye className="w-3 h-3 mr-1" />
                      로그
                    </Button>
                    {job.status !== "실행중" && (
                      <Button size="sm" variant="outline">
                        <RotateCcw className="w-3 h-3 mr-1" />
                        재실행
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
