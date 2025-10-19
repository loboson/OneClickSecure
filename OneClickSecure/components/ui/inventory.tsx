"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Server,
  Plus,
  Search,
  Trash2,
  Play,
  CheckCircle,
  FileText,
  Calendar,
  User,
  Loader2,
  FileDown,
} from "lucide-react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogTrigger } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { useRouter } from "next/navigation"

interface Host {
  id: number
  name: string
  username: string
  ip: string
  os?: string
  created_at?: string
}

export function Inventory() {
  const [searchTerm, setSearchTerm] = useState("")
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [hosts, setHosts] = useState<Host[]>([])
  const [newHost, setNewHost] = useState({ name: "", username: "", password: "", ip: "" })
  const [checkResult, setCheckResult] = useState<string | null>(null)
  const [checkModalOpen, setCheckModalOpen] = useState(false)
  const [checkingId, setCheckingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [checkPassword, setCheckPassword] = useState("")
  const [checkHostObj, setCheckHostObj] = useState<Host | null>(null)
  const [checkDone, setCheckDone] = useState(false)
  const [downloadLoading, setDownloadLoading] = useState(false)
  const [downloadFileName, setDownloadFileName] = useState("")
  const [error, setError] = useState<string | null>(null)
  
  const router = useRouter()

  // 호스트 목록 불러오기
  const fetchHosts = async () => {
    try {
      setError(null)
      const res = await fetch("http://localhost:8000/inventory/list")
      
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`)
      }
      
      const data = await res.json()
      if (Array.isArray(data)) {
        setHosts(data)
      } else {
        setHosts([])
        setError("잘못된 데이터 형식을 받았습니다")
      }
    } catch (error) {
      console.error("호스트 목록 조회 오류:", error)
      setHosts([])
      setError(error instanceof Error ? error.message : "호스트 목록 불러오기 실패")
    }
  }

  useEffect(() => {
    fetchHosts()
  }, [])

  const handleInputChange = (field: string, value: string) => {
    setNewHost((prev) => ({ ...prev, [field]: value }))
  }

  // 호스트 추가
  const handleAddHost = async () => {
    if (!newHost.name.trim() || !newHost.username.trim() || !newHost.password.trim() || !newHost.ip.trim()) {
      alert("모든 필드를 입력해주세요.")
      return
    }

    try {
      setError(null)
      const response = await fetch("http://localhost:8000/inventory/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newHost),
      })
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || "등록 실패")
      }

      await fetchHosts()
      setIsCreateDialogOpen(false)
      setNewHost({ name: "", username: "", password: "", ip: "" })
      alert("호스트가 성공적으로 등록되었습니다.")
    } catch (e) {
      console.error("호스트 등록 오류:", e)
      const errorMessage = e instanceof Error ? e.message : "호스트 등록 실패"
      setError(errorMessage)
      alert(errorMessage)
    }
  }

  // 점검 버튼 클릭 시
  const handleCheckHost = (host: Host) => {
    setCheckHostObj(host)
    setCheckPassword("")
    setCheckResult(null)
    setCheckDone(false)
    setError(null)
    setCheckModalOpen(true)
  }

  // 점검 실행
  const handleDoCheck = async () => {
    if (!checkHostObj || !checkPassword.trim()) {
      alert("비밀번호를 입력해주세요.")
      return
    }

    setCheckingId(checkHostObj.id)
    setCheckResult(null)
    setCheckDone(false)
    setError(null)
    
    try {
      const response = await fetch("http://localhost:8000/inventory/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: checkHostObj.username,
          password: checkPassword,
          ip: checkHostObj.ip,
        }),
      })
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || "점검 실행 실패")
      }

      const result = await response.json()
      setCheckResult(result.result || result.message || "점검이 완료되었습니다.")
      setCheckDone(true)
      
    } catch (e) {
      console.error("점검 실행 오류:", e)
      const errorMessage = e instanceof Error ? e.message : "점검 실행 실패"
      setCheckResult(`점검 실패: ${errorMessage}`)
      setError(errorMessage)
      setCheckDone(false)
    } finally {
      setCheckingId(null)
    }
  }

  // 파일 다운로드
  const handleDownload = async () => {
    if (!checkHostObj) return

    setDownloadLoading(true)
    setError(null)

    try {
      const response = await fetch(
        `http://localhost:8000/api/download/${checkHostObj.id}/${checkHostObj.username}`,
        { credentials: "include" }
      )

      if (!response.ok) {
        throw new Error("다운로드 실패")
      }

      const contentDisposition = response.headers.get("content-disposition")
      if (!contentDisposition) {
        throw new Error("서버에서 파일명을 제공하지 않았습니다.")
      }

      // 파일명 추출
      let fileName = "result.csv"
      let match = contentDisposition.match(/filename\*=utf-8''([^;]+)/i)
      if (match && match[1]) {
        fileName = decodeURIComponent(match[1])
      } else {
        match = contentDisposition.match(/filename="?([^";]+)"?/)
        if (match && match[1]) {
          fileName = decodeURIComponent(match[1])
        }
      }

      setDownloadFileName(fileName)

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url
      link.setAttribute("download", fileName)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

    } catch (error) {
      console.error("다운로드 오류:", error)
      const errorMessage = error instanceof Error ? error.message : "다운로드 실패"
      setError(errorMessage)
      alert(errorMessage)
    } finally {
      setDownloadLoading(false)
    }
  }

  // 호스트 삭제
  const handleDeleteHost = async (hostId: number) => {
    if (!window.confirm("정말 삭제하시겠습니까?")) return

    setDeletingId(hostId)
    setError(null)

    try {
      const response = await fetch(`http://localhost:8000/inventory/delete/${hostId}`, {
        method: "DELETE",
      })
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || "삭제 실패")
      }

      await fetchHosts()
      alert("호스트가 성공적으로 삭제되었습니다.")
    } catch (e) {
      console.error("호스트 삭제 오류:", e)
      const errorMessage = e instanceof Error ? e.message : "호스트 삭제 실패"
      setError(errorMessage)
      alert(errorMessage)
    } finally {
      setDeletingId(null)
    }
  }

  // 상세 결과 보기
  const handleShowAuditResult = () => {
    if (!checkHostObj) return
    const params = new URLSearchParams({
      id: String(checkHostObj.id),
      username: checkHostObj.username,
      name: checkHostObj.name,
      ip: checkHostObj.ip,
    })
    router.push(`/audit-result?${params.toString()}`)
  }

  const filteredHosts = hosts.filter(
    (host) =>
      host.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      host.ip.includes(searchTerm)
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">인벤토리</h1>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button className="bg-blue-600 hover:bg-blue-700">
              <Plus className="w-4 h-4 mr-2" />
              호스트 추가
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>호스트 추가</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">이름 *</label>
                <Input
                  value={newHost.name}
                  onChange={(e) => handleInputChange("name", e.target.value)}
                  placeholder="예: web-01"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">사용자명 *</label>
                <Input
                  value={newHost.username}
                  onChange={(e) => handleInputChange("username", e.target.value)}
                  placeholder="예: root"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">비밀번호 *</label>
                <Input
                  type="password"
                  value={newHost.password}
                  onChange={(e) => handleInputChange("password", e.target.value)}
                  placeholder="비밀번호 입력"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-700">IP 주소 *</label>
                <Input
                  value={newHost.ip}
                  onChange={(e) => handleInputChange("ip", e.target.value)}
                  placeholder="예: 192.168.1.100"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                취소
              </Button>
              <Button onClick={handleAddHost}>추가</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* 오류 메시지 */}
      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      <Tabs defaultValue="hosts" className="space-y-6">
        <TabsList>
          <TabsTrigger value="hosts">호스트</TabsTrigger>
        </TabsList>
        <TabsContent value="hosts" className="space-y-6">
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <Input
              placeholder="호스트 검색..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredHosts.map((host) => (
              <Card key={host.id} className="hover:shadow-lg transition-shadow">
                <CardHeader className="pb-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Server className="h-5 w-5 text-blue-600" />
                      <CardTitle className="text-lg">{host.name}</CardTitle>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 w-8 p-0 text-red-500 hover:text-red-700 hover:bg-red-50"
                      onClick={() => handleDeleteHost(host.id)}
                      disabled={deletingId === host.id}
                      title="삭제"
                    >
                      {deletingId === host.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Trash2 className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">IP 주소:</span>
                      <span className="font-mono font-medium">{host.ip}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">사용자:</span>
                      <span className="font-medium">{host.username}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">OS:</span>
                      <span className="font-medium">{host.os || "확인 중..."}</span>
                    </div>
                  </div>
                  <div className="pt-2">
                    <Button
                      className="w-full bg-blue-600 hover:bg-blue-700 text-white h-10"
                      onClick={() => handleCheckHost(host)}
                      disabled={checkingId === host.id}
                    >
                      {checkingId === host.id ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          점검 중...
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-2" />
                          보안 점검
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {filteredHosts.length === 0 && !error && (
            <div className="text-center py-12">
              <Server className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-4 text-lg font-medium text-gray-900">호스트가 없습니다</h3>
              <p className="mt-2 text-sm text-gray-500">
                새 호스트를 추가하여 보안 점검을 시작하세요.
              </p>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* 점검 결과 모달 */}
      <Dialog open={checkModalOpen} onOpenChange={setCheckModalOpen}>
        <DialogContent className="w-[95vw] max-w-4xl h-[80vh] flex flex-col">
          <DialogHeader className="p-4 border-b">
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5 text-blue-600" />
              {checkHostObj?.name} 보안 점검 결과
            </DialogTitle>
          </DialogHeader>
          
          <div className="p-6 space-y-6 overflow-y-auto flex-1">
            {/* 호스트 정보 */}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-600" />
                <span className="text-gray-500">호스트:</span>
                <span className="font-medium">{checkHostObj?.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <User className="h-4 w-4 text-blue-600" />
                <span className="text-gray-500">사용자:</span>
                <span className="font-medium">{checkHostObj?.username}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-500">IP:</span>
                <span className="font-mono font-medium">{checkHostObj?.ip}</span>
              </div>
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-blue-600" />
                <span className="text-gray-500">시간:</span>
                <span className="font-medium">{new Date().toLocaleString()}</span>
              </div>
            </div>

            {/* 비밀번호 입력 */}
            {!checkDone && (
              <div className="p-4 border rounded-lg bg-gray-50">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-700">접속 비밀번호</label>
                  <Input
                    type="password"
                    placeholder="호스트 접속용 비밀번호를 입력하세요"
                    value={checkPassword}
                    onChange={(e) => setCheckPassword(e.target.value)}
                    disabled={checkingId !== null}
                    onKeyPress={(e) => e.key === 'Enter' && handleDoCheck()}
                  />
                </div>
              </div>
            )}

            {/* 점검 결과 */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-lg">
                  {checkingId ? "점검 실행 중..." : checkDone ? "점검 결과" : "점검 준비"}
                </h3>
                {checkDone && (
                  <Badge className="bg-green-100 text-green-800 border-green-200">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    완료
                  </Badge>
                )}
              </div>

              <div className="border rounded-lg overflow-hidden">
                {checkingId ? (
                  <div className="h-64 flex flex-col items-center justify-center bg-gray-50">
                    <Loader2 className="h-8 w-8 animate-spin text-blue-600 mb-4" />
                    <p className="text-blue-800 font-medium">보안 점검을 실행하고 있습니다...</p>
                    <p className="text-sm text-gray-600 mt-2">잠시만 기다려주세요</p>
                  </div>
                ) : checkDone ? (
                  <div className="space-y-4">
                    <div className="bg-green-50 p-4 border-b border-green-100">
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-green-600" />
                        <span className="text-green-800 font-medium">점검이 완료되었습니다!</span>
                      </div>
                    </div>
                    {checkResult && (
                      <div className="p-4">
                        <pre className="whitespace-pre-wrap text-sm bg-gray-50 p-4 rounded max-h-96 overflow-y-auto">
                          {checkResult}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="h-64 flex items-center justify-center bg-gray-50">
                    <p className="text-gray-500">비밀번호를 입력하고 점검을 시작하세요</p>
                  </div>
                )}
              </div>
            </div>

            {/* 다운로드 및 상세보기 */}
            {checkDone && (
              <div className="space-y-4">
                <div className="border rounded-lg p-4 bg-blue-50">
                  <div className="flex items-center gap-2 mb-2">
                    <FileText className="h-5 w-5 text-blue-600" />
                    <h4 className="font-medium text-blue-800">결과 파일</h4>
                  </div>
                  {downloadFileName && (
                    <p className="text-sm text-gray-600 mb-3">
                      파일명: <span className="font-mono">{downloadFileName}</span>
                    </p>
                  )}
                  <div className="flex gap-2">
                    <Button
                      onClick={handleDownload}
                      disabled={downloadLoading}
                      className="flex-1"
                      variant="outline"
                    >
                      {downloadLoading ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          다운로드 중...
                        </>
                      ) : (
                        <>
                          <FileDown className="w-4 h-4 mr-2" />
                          CSV 다운로드
                        </>
                      )}
                    </Button>
                    <Button onClick={handleShowAuditResult} className="flex-1">
                      <FileText className="w-4 h-4 mr-2" />
                      상세 결과 보기
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* 하단 버튼 */}
          <div className="p-4 border-t bg-gray-50 flex justify-end gap-2">
            {!checkDone && (
              <Button
                onClick={handleDoCheck}
                disabled={checkingId !== null || !checkPassword.trim()}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {checkingId ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    점검 중...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    점검 시작
                  </>
                )}
              </Button>
            )}
            <Button variant="outline" onClick={() => setCheckModalOpen(false)}>
              닫기
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}