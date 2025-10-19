// components/ui/playbooks.tsx

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import { 
  Plus, 
  FileText,
  Download,
  Copy,
  Code,
  Trash2,
  Monitor,
  RefreshCw,
  AlertCircle,
  X,
  CheckCircle,
  Play,
  Server,
  User,
  Loader2,
  CheckSquare,
  Square,
  Edit,
  FileEdit
} from 'lucide-react'

// YAML 에디터 컴포넌트 import
import { YAMLEditor } from '@/components/ui/yaml-editor'

const API_BASE_URL = 'http://localhost:8000'

interface ScriptSection {
  id: string
  name: string
  description: string
  content: string
}

interface Playbook {
  id: number
  name: string
  description: string
  lastRun: string
  status: "성공" | "실패" | "대기중"
  tasks: number
  filename?: string
  sections?: ScriptSection[]
  type?: string
}

interface HostInfo {
  id: number
  name: string
  ip: string
  username: string
  os?: string
}

interface ExecutionResult {
  hostname: string
  ip: string
  success: boolean
  output: string
  return_code: number
  completed_at: string
}

export function Playbooks() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [hosts, setHosts] = useState<HostInfo[]>([])
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isYamlEditorOpen, setIsYamlEditorOpen] = useState(false)
  const [isExecuteDialogOpen, setIsExecuteDialogOpen] = useState(false)
  const [isSectionDialogOpen, setIsSectionDialogOpen] = useState(false)
  const [isResultDialogOpen, setIsResultDialogOpen] = useState(false)
  const [isScriptViewDialogOpen, setIsScriptViewDialogOpen] = useState(false)
  
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [selectedSections, setSelectedSections] = useState<string[]>([])
  const [selectedHosts, setSelectedHosts] = useState<number[]>([])
  const [password, setPassword] = useState('')
  const [scriptContent, setScriptContent] = useState<string>('')
  
  // YAML 에디터 관련 상태
  const [yamlContent, setYamlContent] = useState<string>('')
  const [isYamlValid, setIsYamlValid] = useState<boolean>(false)
  const [editingPlaybook, setEditingPlaybook] = useState<Playbook | null>(null)
  
  const [loading, setLoading] = useState(false)
  const [executionId, setExecutionId] = useState<string | null>(null)
  const [executionResults, setExecutionResults] = useState<{[key: number]: ExecutionResult}>({})
  const [error, setError] = useState<string | null>(null)

  // 새 플레이북 생성 상태
  const [newPlaybook, setNewPlaybook] = useState({
    name: '',
    description: '',
    file: null as File | null
  })

  useEffect(() => {
    fetchPlaybooks()
    fetchHosts()
  }, [])

  // 플레이북 목록 조회
  const fetchPlaybooks = async () => {
    try {
      console.log("🔄 플레이북 목록 조회 중...")
      setError(null)
      
      const response = await fetch(`${API_BASE_URL}/api/playbooks`)
      
      if (response.ok) {
        const data = await response.json()
        console.log("📋 조회된 플레이북:", data)
        setPlaybooks(data)
      } else {
        const errorText = await response.text()
        console.error("❌ 플레이북 조회 실패:", response.status, errorText)
        setError(`플레이북 조회 실패: ${response.status}`)
        setPlaybooks([])
      }
    } catch (error) {
      console.error("💥 네트워크 오류:", error)
      setError(`네트워크 오류: ${error instanceof Error ? error.message : '알 수 없는 오류'}`)
      setPlaybooks([])
    }
  }

  // 호스트 목록 조회
  const fetchHosts = async () => {
    try {
      console.log("🔄 호스트 목록 조회 중...")
      
      const response = await fetch(`${API_BASE_URL}/api/playbooks/hosts`)
      if (response.ok) {
        const data = await response.json()
        setHosts(data)
        console.log("🖥️ 조회된 호스트:", data)
      } else {
        console.warn("⚠️ 호스트 목록 조회 실패, 빈 리스트 사용")
        setHosts([])
      }
    } catch (error) {
      console.error("💥 호스트 조회 오류:", error)
      setHosts([])
    }
  }

  // API 연결 테스트
  const testConnection = async () => {
    try {
      console.log("🔧 API 연결 테스트 중...")
      setError(null)
      
      const response = await fetch(`${API_BASE_URL}/api/playbooks/health`)
      if (response.ok) {
        const data = await response.json()
        console.log("✅ API 연결 성공:", data)
        alert(`API 연결 성공!\n상태: ${data.status}\n플레이북 개수: ${data.playbooks_count}\n스크립트 파일: ${data.actual_script_files?.length || 0}개`)
      } else {
        console.error("❌ API 연결 실패:", response.status)
        alert(`API 연결 실패: ${response.status}`)
      }
    } catch (error) {
      console.error("💥 연결 테스트 오류:", error)
      setError(`연결 테스트 실패: ${error}`)
      alert(`연결 테스트 실패: ${error}`)
    }
  }

  // YAML 에디터 열기 (새 플레이북)
  const openYamlEditor = () => {
    setEditingPlaybook(null)
    setYamlContent('')
    setIsYamlEditorOpen(true)
  }

  // YAML 에디터 열기 (기존 플레이북 편집)
  const editPlaybookWithYaml = async (playbook: Playbook) => {
    if (!playbook.filename || !playbook.filename.endsWith('.yml') && !playbook.filename.endsWith('.yaml')) {
      alert('YAML 파일만 편집할 수 있습니다.')
      return
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/playbooks/${playbook.id}/script`)
      if (response.ok) {
        const result = await response.json()
        setEditingPlaybook(playbook)
        setYamlContent(result.script_content)
        setIsYamlEditorOpen(true)
      } else {
        alert('플레이북 내용을 불러올 수 없습니다.')
      }
    } catch (error) {
      alert('플레이북 내용을 불러오는 중 오류가 발생했습니다.')
    }
  }

  // YAML 에디터에서 저장
  const saveYamlPlaybook = async () => {
    if (!isYamlValid || !yamlContent.trim()) {
      alert('유효한 YAML 내용을 입력해주세요.')
      return
    }

    try {
      // Blob으로 파일 생성
      const blob = new Blob([yamlContent], { type: 'text/yaml' })
      const file = new File([blob], 'playbook.yml', { type: 'text/yaml' })

      const formData = new FormData()
      
      if (editingPlaybook) {
        // 기존 플레이북 업데이트 로직 (API가 지원한다면)
        alert('플레이북 업데이트 기능은 아직 구현되지 않았습니다.')
        return
      } else {
        // 새 플레이북 생성
        const name = prompt('플레이북 이름을 입력하세요:')
        const description = prompt('플레이북 설명을 입력하세요:') || ''
        
        if (!name) return
        
        formData.append('name', name)
        formData.append('description', description)
        formData.append('file', file)
      }

      const response = await fetch(`${API_BASE_URL}/api/playbooks`, {
        method: 'POST',
        body: formData
      })

      if (response.ok) {
        const newPlaybookData = await response.json()
        setPlaybooks(prev => [...prev, newPlaybookData])
        setIsYamlEditorOpen(false)
        setYamlContent('')
        setEditingPlaybook(null)
        alert('플레이북이 성공적으로 저장되었습니다.')
        fetchPlaybooks() // 목록 새로고침
      } else {
        const errorData = await response.json()
        alert(`저장 실패: ${errorData.detail || '알 수 없는 오류'}`)
      }
    } catch (error) {
      alert('저장 중 오류가 발생했습니다.')
    }
  }

  // 플레이북 생성 (파일 업로드)
  const handleCreatePlaybook = async () => {
    if (!newPlaybook.name.trim()) {
      alert('플레이북 이름을 입력해주세요.')
      return
    }

    try {
      setError(null)
      const formData = new FormData()
      formData.append('name', newPlaybook.name)
      formData.append('description', newPlaybook.description)
      if (newPlaybook.file) {
        formData.append('file', newPlaybook.file)
      }

      const response = await fetch(`${API_BASE_URL}/api/playbooks`, {
        method: 'POST',
        body: formData
      })

      if (response.ok) {
        const newPlaybookData = await response.json()
        setPlaybooks(prev => [...prev, newPlaybookData])
        setIsCreateDialogOpen(false)
        setNewPlaybook({ name: '', description: '', file: null })
        console.log("✅ 플레이북 생성 성공:", newPlaybookData)
        alert('플레이북이 성공적으로 생성되었습니다.')
      } else {
        const errorData = await response.json()
        const errorMessage = errorData.detail || '알 수 없는 오류'
        setError(errorMessage)
        alert(`생성 실패: ${errorMessage}`)
      }
    } catch (error) {
      console.error("💥 플레이북 생성 오류:", error)
      const errorMessage = '네트워크 오류가 발생했습니다.'
      setError(errorMessage)
      alert(errorMessage)
    }
  }

  // 플레이북 삭제
  const handleDeletePlaybook = async (playbookId: number) => {
    if (!confirm('정말로 이 플레이북을 삭제하시겠습니까?')) {
      return
    }

    try {
      setError(null)
      const response = await fetch(`${API_BASE_URL}/api/playbooks/${playbookId}`, {
        method: 'DELETE'
      })

      if (response.ok) {
        setPlaybooks(prev => prev.filter(p => p.id !== playbookId))
        console.log("✅ 플레이북 삭제 성공")
        alert('플레이북이 성공적으로 삭제되었습니다.')
      } else {
        const errorData = await response.json()
        const errorMessage = errorData.detail || '알 수 없는 오류'
        setError(errorMessage)
        alert(`삭제 실패: ${errorMessage}`)
      }
    } catch (error) {
      console.error("💥 플레이북 삭제 오류:", error)
      const errorMessage = '네트워크 오류가 발생했습니다.'
      setError(errorMessage)
      alert(errorMessage)
    }
  }

  // 실행 준비 (호스트 선택 모달 열기)
  const handlePrepareExecution = (playbook: Playbook) => {
    setSelectedPlaybook(playbook)
    setSelectedHosts([])
    setPassword('')
    setSelectedSections([])
    setIsExecuteDialogOpen(true)
  }

  // 섹션 선택 모달 열기
  const handleSelectSections = () => {
    if (!selectedPlaybook?.sections || selectedPlaybook.sections.length <= 1) {
      // 섹션이 없거나 1개뿐이면 바로 실행
      handleExecutePlaybook()
      return
    }
    setIsSectionDialogOpen(true)
  }

  // 플레이북 실행
  const handleExecutePlaybook = async () => {
    if (!selectedPlaybook || selectedHosts.length === 0 || !password.trim()) {
      alert('플레이북, 호스트, 비밀번호를 모두 입력해주세요.')
      return
    }

    setLoading(true)
    setIsExecuteDialogOpen(false)
    setIsSectionDialogOpen(false)

    try {
      const requestBody = {
        host_ids: selectedHosts,
        password: password,
        section_ids: selectedSections.length > 0 ? selectedSections : undefined
      }

      console.log("🚀 플레이북 실행 요청:", requestBody)

      const response = await fetch(`${API_BASE_URL}/api/playbooks/${selectedPlaybook.id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      })

      if (response.ok) {
        const result = await response.json()
        console.log("✅ 플레이북 실행 시작:", result)
        
        setExecutionId(result.execution_id)
        
        // 실행 상태 모니터링 시작
        monitorExecution(result.execution_id)
      } else {
        const errorData = await response.json()
        setError(errorData.detail || '알 수 없는 오류')
        alert(`실행 실패: ${errorData.detail || '알 수 없는 오류'}`)
        setLoading(false)
      }
    } catch (error) {
      console.error("💥 플레이북 실행 오류:", error)
      setError('네트워크 오류가 발생했습니다.')
      alert('네트워크 오류가 발생했습니다.')
      setLoading(false)
    }
  }

  // 실행 상태 모니터링
  const monitorExecution = async (execId: string) => {
    const maxAttempts = 60 // 5분간 모니터링
    let attempts = 0

    const checkStatus = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/playbooks/execution/${execId}`)
        if (response.ok) {
          const status = await response.json()
          console.log("📊 실행 상태:", status)

          if (status.status === "완료" || status.status === "실패") {
            setLoading(false)
            setExecutionResults(status.results || {})
            setIsResultDialogOpen(true)
            
            // 플레이북 상태 업데이트
            setPlaybooks(prev => prev.map(p => 
              p.id === selectedPlaybook?.id 
                ? { ...p, status: status.status === "완료" ? "성공" : "실패", lastRun: "방금 전" }
                : p
            ))
            return
          } else if (status.status === "실행중") {
            attempts++
            if (attempts < maxAttempts) {
              setTimeout(checkStatus, 5000) // 5초 후 다시 확인
            } else {
              setLoading(false)
              alert("실행 시간이 초과되었습니다.")
            }
          }
        } else {
          setLoading(false)
          alert("실행 상태 확인 실패")
        }
      } catch (error) {
        console.error("💥 상태 확인 오류:", error)
        setLoading(false)
        alert("실행 상태 확인 중 오류 발생")
      }
    }

    // 첫 번째 상태 확인 (2초 후)
    setTimeout(checkStatus, 2000)
  }

  // 스크립트 내용 보기
  const handleViewScript = async (playbook: Playbook) => {
    if (!playbook.filename) {
      alert('이 플레이북에는 스크립트 파일이 없습니다.')
      return
    }

    try {
      setError(null)
      console.log("📄 스크립트 가져오기:", playbook.id)
      
      const response = await fetch(`${API_BASE_URL}/api/playbooks/${playbook.id}/script`)
      
      if (response.ok) {
        const result = await response.json()
        console.log("✅ 스크립트 가져오기 성공:", result)
        
        setSelectedPlaybook(playbook)
        setScriptContent(result.script_content)
        setIsScriptViewDialogOpen(true)
      } else {
        const errorData = await response.json()
        const errorMessage = errorData.detail || '알 수 없는 오류'
        setError(errorMessage)
        alert(`스크립트 가져오기 실패: ${errorMessage}`)
      }
    } catch (error) {
      console.error("💥 스크립트 가져오기 오류:", error)
      const errorMessage = '네트워크 오류가 발생했습니다.'
      setError(errorMessage)
      alert(errorMessage)
    }
  }

  // 스크립트 다운로드
  const handleDownloadScript = async (playbookId: number) => {
    try {
      setError(null)
      console.log("📥 스크립트 다운로드:", playbookId)
      
      const response = await fetch(`${API_BASE_URL}/api/playbooks/${playbookId}/script/download`)
      
      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.style.display = 'none'
        a.href = url
        
        // 파일명 추출
        const contentDisposition = response.headers.get('Content-Disposition')
        let filename = 'script.sh'
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="(.+)"/)
          if (filenameMatch) {
            filename = filenameMatch[1]
          }
        }
        
        a.download = filename
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        
        console.log("✅ 스크립트 다운로드 완료:", filename)
      } else {
        const errorData = await response.json()
        const errorMessage = errorData.detail || '알 수 없는 오류'
        setError(errorMessage)
        alert(`다운로드 실패: ${errorMessage}`)
      }
    } catch (error) {
      console.error("💥 다운로드 오류:", error)
      const errorMessage = '다운로드 중 오류가 발생했습니다.'
      setError(errorMessage)
      alert(errorMessage)
    }
  }

  // 호스트 선택/해제
  const handleHostToggle = (hostId: number) => {
    setSelectedHosts(prev => 
      prev.includes(hostId) ? prev.filter(id => id !== hostId) : [...prev, hostId]
    )
  }

  // 섹션 선택/해제
  const handleSectionToggle = (sectionId: string) => {
    setSelectedSections(prev => 
      prev.includes(sectionId) ? prev.filter(id => id !== sectionId) : [...prev, sectionId]
    )
  }

  // 전체 선택/해제
  const handleSelectAll = (type: 'hosts' | 'sections') => {
    if (type === 'hosts') {
      if (selectedHosts.length === hosts.length) {
        setSelectedHosts([])
      } else {
        setSelectedHosts(hosts.map(h => h.id))
      }
    } else {
      if (!selectedPlaybook?.sections) return
      
      if (selectedSections.length === selectedPlaybook.sections.length) {
        setSelectedSections([])
      } else {
        setSelectedSections(selectedPlaybook.sections.map(s => s.id))
      }
    }
  }

  // 클립보드에 복사
  const handleCopyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(scriptContent)
      alert('스크립트가 클립보드에 복사되었습니다!')
    } catch (error) {
      console.error("클립보드 복사 실패:", error)
      alert('클립보드 복사에 실패했습니다.')
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "성공": return "bg-green-100 text-green-800"
      case "실패": return "bg-red-100 text-red-800"
      default: return "bg-gray-100 text-gray-800"
    }
  }

  const getFileTypeIcon = (filename?: string) => {
    if (!filename) return <FileText className="h-4 w-4" />
    
    if (filename.endsWith('.sh')) return <Code className="h-4 w-4" />
    if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return <FileEdit className="h-4 w-4" />
    if (filename.endsWith('.py')) return <Code className="h-4 w-4" />
    return <FileText className="h-4 w-4" />
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">플레이북 관리</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={testConnection} disabled={loading}>
            <Monitor className="mr-2 h-4 w-4" />
            연결 테스트
          </Button>
          <Button variant="outline" onClick={fetchPlaybooks} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            새로고침
          </Button>
          <Button variant="outline" onClick={openYamlEditor}>
            <FileEdit className="mr-2 h-4 w-4" />
            YAML 에디터
          </Button>
          <Button onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            파일 업로드
          </Button>
        </div>
      </div>

      {/* 오류 메시지 */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center">
          <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
          <span className="text-red-800 flex-1">{error}</span>
          <Button 
            variant="ghost" 
            size="sm" 
            onClick={() => setError(null)}
            className="ml-2"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* 플레이북 카드 목록 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {playbooks.map((playbook) => (
          <Card key={playbook.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg flex items-center gap-2">
                  {getFileTypeIcon(playbook.filename)}
                  {playbook.name}
                </CardTitle>
                <Badge className={getStatusColor(playbook.status)}>
                  {playbook.status}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4 text-sm">{playbook.description}</p>
              
              <div className="space-y-2 mb-4">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Tasks:</span>
                  <span className="font-medium">{playbook.tasks}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">마지막 실행:</span>
                  <span className="font-medium">{playbook.lastRun}</span>
                </div>
                {playbook.filename && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">파일:</span>
                    <span className="font-medium text-xs">{playbook.filename}</span>
                  </div>
                )}
                {playbook.sections && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">섹션:</span>
                    <span className="font-medium">{playbook.sections.length}개</span>
                  </div>
                )}
              </div>

              <div className="flex gap-1 mb-2">
                <Button 
                  onClick={() => handlePrepareExecution(playbook)}
                  size="sm"
                  className="flex-1"
                  disabled={loading || !playbook.filename}
                >
                  <Play className="mr-1 h-3 w-3" />
                  실행
                </Button>

                {/* YAML 파일이면 편집 버튼 추가 */}
                {playbook.filename?.endsWith('.yml') || playbook.filename?.endsWith('.yaml') ? (
                  <Button 
                    onClick={() => editPlaybookWithYaml(playbook)}
                    size="sm"
                    variant="outline"
                    title="YAML 편집"
                  >
                    <Edit className="h-3 w-3" />
                  </Button>
                ) : (
                  <Button 
                    onClick={() => handleViewScript(playbook)}
                    size="sm"
                    variant="outline"
                    disabled={!playbook.filename}
                    title="스크립트 보기"
                  >
                    <FileText className="h-3 w-3" />
                  </Button>
                )}

                <Button 
                  onClick={() => handleDownloadScript(playbook.id)}
                  size="sm"
                  variant="outline"
                  disabled={!playbook.filename}
                  title="다운로드"
                >
                  <Download className="h-3 w-3" />
                </Button>

                <Button 
                  onClick={() => handleDeletePlaybook(playbook.id)}
                  size="sm"
                  variant="outline"
                  className="text-red-600 hover:text-red-700"
                  title="삭제"
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* 플레이북이 없을 때 */}
      {playbooks.length === 0 && !error && !loading && (
        <div className="text-center py-12">
          <FileText className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-4 text-lg font-medium text-gray-900">플레이북이 없습니다</h3>
          <p className="mt-2 text-sm text-gray-500">
            새 플레이북을 추가하거나 기존 스크립트를 스캔해주세요.
          </p>
          <div className="mt-4 flex gap-2 justify-center">
            <Button onClick={openYamlEditor}>
              <FileEdit className="mr-2 h-4 w-4" />
              YAML 에디터
            </Button>
            <Button variant="outline" onClick={() => setIsCreateDialogOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              파일 업로드
            </Button>
            <Button variant="outline" onClick={fetchPlaybooks}>
              <RefreshCw className="mr-2 h-4 w-4" />
              스캔
            </Button>
          </div>
        </div>
      )}

      {/* YAML 에디터 다이얼로그 */}
      <Dialog open={isYamlEditorOpen} onOpenChange={setIsYamlEditorOpen}>
        <DialogContent className="sm:max-w-[95vw] lg:max-w-[85vw] xl:max-w-[80vw] max-h-[95vh] overflow-hidden flex flex-col">
          <DialogHeader className="flex-shrink-0">
            <DialogTitle>
              {editingPlaybook ? `${editingPlaybook.name} 편집` : 'YAML 플레이북 에디터'}
            </DialogTitle>
            <DialogDescription>
              {editingPlaybook ? '기존 플레이북을 편집합니다.' : '새로운 YAML 플레이북을 작성합니다.'}
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-hidden min-h-0">
            <YAMLEditor
              initialContent={yamlContent}
              onValidationChange={(isValid, result) => {
                setIsYamlValid(isValid)
              }}
              onContentChange={(content) => {
                setYamlContent(content)
              }}
              height="calc(95vh - 200px)"
            />
          </div>
          <DialogFooter className="flex-shrink-0 mt-4">
            <Button variant="outline" onClick={() => setIsYamlEditorOpen(false)}>
              취소
            </Button>
            <Button onClick={saveYamlPlaybook} disabled={!isYamlValid || !yamlContent.trim()}>
              <CheckCircle className="mr-2 h-4 w-4" />
              저장
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 플레이북 생성 다이얼로그 */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="sm:max-w-[425px]">
          <DialogHeader>
            <DialogTitle>파일 업로드로 플레이북 생성</DialogTitle>
            <DialogDescription>
              스크립트 파일을 업로드하여 플레이북을 생성합니다.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">플레이북 이름 *</Label>
              <Input
                id="name"
                value={newPlaybook.name}
                onChange={(e) => setNewPlaybook(prev => ({ ...prev, name: e.target.value }))}
                placeholder="플레이북 이름을 입력하세요"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="description">설명</Label>
              <Textarea
                id="description"
                value={newPlaybook.description}
                onChange={(e) => setNewPlaybook(prev => ({ ...prev, description: e.target.value }))}
                placeholder="플레이북 설명을 입력하세요"
                rows={3}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="file">스크립트 파일 업로드 *</Label>
              <Input
                id="file"
                type="file"
                accept=".sh,.py,.yml,.yaml"
                onChange={(e) => setNewPlaybook(prev => ({ 
                  ...prev, 
                  file: e.target.files ? e.target.files[0] : null 
                }))}
              />
              <p className="text-xs text-gray-500">
                지원 형식: .sh, .py, .yml, .yaml
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
              취소
            </Button>
            <Button onClick={handleCreatePlaybook}>생성</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 호스트 선택 다이얼로그 */}
      <Dialog open={isExecuteDialogOpen} onOpenChange={setIsExecuteDialogOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>플레이북 실행 - 호스트 선택</DialogTitle>
            <DialogDescription>
              {selectedPlaybook?.name}을(를) 실행할 호스트를 선택하세요
            </DialogDescription>
          </DialogHeader>
          <div className="py-4 space-y-4">
            {/* 호스트 선택 */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <Label>실행할 호스트 선택</Label>
                <Button
                  onClick={() => handleSelectAll('hosts')}
                  variant="outline"
                  size="sm"
                >
                  {selectedHosts.length === hosts.length ? "전체 해제" : "전체 선택"}
                </Button>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto border rounded p-2">
                {hosts.map((host) => (
                  <div 
                    key={host.id}
                    className="flex items-center space-x-3 p-2 border rounded cursor-pointer hover:bg-gray-50"
                    onClick={() => handleHostToggle(host.id)}
                  >
                    {selectedHosts.includes(host.id) ? (
                      <CheckSquare className="h-4 w-4 text-blue-600" />
                    ) : (
                      <Square className="h-4 w-4 text-gray-400" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-blue-600" />
                        <span className="font-medium">{host.name}</span>
                        <span className="text-sm text-gray-500">({host.ip})</span>
                      </div>
                      <div className="text-xs text-gray-500">
                        사용자: {host.username} | OS: {host.os || '미확인'}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-2">
                {selectedHosts.length}/{hosts.length} 호스트 선택됨
              </p>
            </div>

            {/* 비밀번호 입력 */}
            <div>
              <Label htmlFor="password">SSH 비밀번호</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="호스트 접속용 비밀번호를 입력하세요"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsExecuteDialogOpen(false)}>
              취소
            </Button>
            <Button 
              onClick={handleSelectSections}
              disabled={selectedHosts.length === 0 || !password.trim()}
            >
              다음: 섹션 선택
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 섹션 선택 다이얼로그 */}
      <Dialog open={isSectionDialogOpen} onOpenChange={setIsSectionDialogOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>실행할 섹션 선택</DialogTitle>
            <DialogDescription>
              {selectedPlaybook?.name}에서 실행할 섹션을 선택하세요 (선택사항)
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="flex items-center gap-2 mb-4">
              <Button
                onClick={() => handleSelectAll('sections')}
                variant="outline"
                size="sm"
              >
                {selectedSections.length === selectedPlaybook?.sections?.length ? 
                  "전체 해제" : "전체 선택"}
              </Button>
              <span className="text-sm text-gray-500">
                {selectedSections.length}/{selectedPlaybook?.sections?.length || 0} 선택됨
              </span>
            </div>
            
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {selectedPlaybook?.sections?.map((section) => (
                <div 
                  key={section.id}
                  className="flex items-center space-x-3 p-3 border rounded-lg hover:bg-gray-50 cursor-pointer"
                  onClick={() => handleSectionToggle(section.id)}
                >
                  {selectedSections.includes(section.id) ? (
                    <CheckSquare className="h-4 w-4 text-blue-600" />
                  ) : (
                    <Square className="h-4 w-4 text-gray-400" />
                  )}
                  <div className="flex-1">
                    <div className="font-medium text-sm">{section.name}</div>
                    <div className="text-xs text-gray-500">{section.description}</div>
                  </div>
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              아무것도 선택하지 않으면 전체 스크립트가 실행됩니다.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsSectionDialogOpen(false)}>
              이전
            </Button>
            <Button onClick={handleExecutePlaybook}>
              <Play className="mr-2 h-4 w-4" />
              실행 시작
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 실행 결과 다이얼로그 */}
      <Dialog open={isResultDialogOpen} onOpenChange={setIsResultDialogOpen}>
        <DialogContent className="sm:max-w-[90vw] lg:max-w-[800px] max-h-[90vh] overflow-hidden flex flex-col">
          <DialogHeader className="flex-shrink-0">
            <DialogTitle>실행 결과</DialogTitle>
            <DialogDescription>
              {selectedPlaybook?.name} 실행 결과입니다
            </DialogDescription>
          </DialogHeader>
          <div className="py-4 space-y-4 overflow-y-auto flex-1 min-h-0">
            {Object.entries(executionResults).map(([hostId, result]) => (
              <div key={hostId} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4" />
                    <span className="font-medium">{result.hostname}</span>
                    <span className="text-sm text-gray-500">({result.ip})</span>
                  </div>
                  <Badge className={result.success ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}>
                    {result.success ? "성공" : "실패"}
                  </Badge>
                </div>
                <div className="bg-gray-50 p-3 rounded text-sm">
                  <pre className="whitespace-pre-wrap max-h-32 overflow-y-auto">
                    {result.output || "출력 없음"}
                  </pre>
                </div>
                <div className="text-xs text-gray-500 mt-2">
                  종료 코드: {result.return_code} | 완료 시간: {new Date(result.completed_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
          <DialogFooter className="flex-shrink-0">
            <Button onClick={() => setIsResultDialogOpen(false)}>
              확인
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 스크립트 보기 다이얼로그 */}
      <Dialog open={isScriptViewDialogOpen} onOpenChange={setIsScriptViewDialogOpen}>
        <DialogContent className="sm:max-w-[90vw] lg:max-w-[800px] max-h-[90vh] overflow-hidden flex flex-col">
          <DialogHeader className="flex-shrink-0">
            <DialogTitle>스크립트 내용</DialogTitle>
            <DialogDescription>
              {selectedPlaybook?.name} - {selectedPlaybook?.filename}
            </DialogDescription>
          </DialogHeader>
          <div className="py-4 flex-1 min-h-0 overflow-hidden">
            <Tabs defaultValue="preview" className="w-full h-full flex flex-col">
              <TabsList className="grid w-full grid-cols-2 flex-shrink-0">
                <TabsTrigger value="preview">미리보기</TabsTrigger>
                <TabsTrigger value="raw">원본</TabsTrigger>
              </TabsList>
              <TabsContent value="preview" className="space-y-4 flex-1 overflow-hidden">
                <div className="bg-gray-50 p-4 rounded-lg h-full overflow-hidden">
                  <pre className="text-sm overflow-auto h-full whitespace-pre-wrap">
                    {scriptContent}
                  </pre>
                </div>
              </TabsContent>
              <TabsContent value="raw" className="space-y-4 flex-1 overflow-hidden">
                <Textarea
                  value={scriptContent}
                  readOnly
                  className="h-full font-mono text-sm resize-none"
                />
              </TabsContent>
            </Tabs>
          </div>
          <DialogFooter className="flex gap-2 flex-shrink-0">
            <Button variant="outline" onClick={() => setIsScriptViewDialogOpen(false)}>
              닫기
            </Button>
            <Button variant="outline" onClick={handleCopyToClipboard}>
              <Copy className="mr-2 h-4 w-4" />
              복사
            </Button>
            <Button onClick={() => {
              if (selectedPlaybook) {
                handleDownloadScript(selectedPlaybook.id)
              }
            }}>
              <Download className="mr-2 h-4 w-4" />
              다운로드
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 로딩 오버레이 */}
      {loading && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg flex items-center space-x-4">
            <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
            <div>
              <div className="font-medium">플레이북 실행 중...</div>
              <div className="text-sm text-gray-500">
                {selectedPlaybook?.name}을(를) {selectedHosts.length}개 호스트에서 실행하고 있습니다.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}