// components/ui/yaml-editor.tsx

"use client"

import React, { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  FileText,
  Download,
  Upload,
  RefreshCw,
  Eye,
  Info,
  Shield,
  Code
} from 'lucide-react'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import {
  Alert,
  AlertDescription,
} from '@/components/ui/alert'

const API_BASE_URL = 'http://localhost:8000'

interface ValidationResult {
  valid: boolean
  syntax_valid: boolean
  structure_valid: boolean
  security_valid: boolean
  syntax_error: string
  structure_issues: string[]
  security_violations: string[]
}

interface YAMLEditorProps {
  initialContent?: string
  onValidationChange?: (isValid: boolean, result: ValidationResult | null) => void
  onContentChange?: (content: string) => void
  readOnly?: boolean
  height?: string
}

const defaultPlaybookTemplate = `---
- name: Security Check Playbook
  hosts: all
  become: true
  gather_facts: true
  
  vars:
    log_file: "/var/log/security_check.log"
  
  tasks:
    - name: Check system information
      setup:
      register: system_info
      tags: ["info"]
    
    - name: Verify important file permissions
      stat:
        path: "{{ item }}"
      register: file_stats
      loop:
        - "/etc/passwd"
        - "/etc/group"
        - "/etc/hosts"
      tags: ["security", "permissions"]
    
    - name: Check running services
      service_facts:
      register: services_info
      tags: ["services"]
    
    - name: Generate security report
      template:
        src: security_report.j2
        dest: "{{ log_file }}"
        mode: '0644'
      tags: ["report"]
`

export function YAMLEditor({ 
  initialContent = "", 
  onValidationChange,
  onContentChange,
  readOnly = false,
  height = "500px"
}: YAMLEditorProps) {
  const [content, setContent] = useState(initialContent || defaultPlaybookTemplate)
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null)
  const [isValidating, setIsValidating] = useState(false)
  const [showTemplate, setShowTemplate] = useState(false)
  const [autoValidate, setAutoValidate] = useState(true)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const validationTimeoutRef = useRef<any>(undefined)

  useEffect(() => {
    if (initialContent && initialContent !== content) {
      setContent(initialContent)
    }
  }, [initialContent])

  useEffect(() => {
    onContentChange?.(content)
    
    if (autoValidate && content.trim()) {
      // 디바운스: 1초 후 검증
      if (validationTimeoutRef.current) {
        clearTimeout(validationTimeoutRef.current)
      }
      
      validationTimeoutRef.current = setTimeout(() => {
        validateContent()
      }, 1000)
    }
    
    return () => {
      if (validationTimeoutRef.current) {
        clearTimeout(validationTimeoutRef.current)
      }
    }
  }, [content, autoValidate])

  const validateContent = async () => {
    if (!content.trim()) return

    setIsValidating(true)
    try {
      const response = await fetch(`${API_BASE_URL}/api/playbooks/validate-yaml`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content })
      })

      if (response.ok) {
        const result: ValidationResult = await response.json()
        setValidationResult(result)
        onValidationChange?.(result.valid, result)
      } else {
        const errorData = await response.json()
        console.error('검증 실패:', errorData)
        setValidationResult({
          valid: false,
          syntax_valid: false,
          structure_valid: false,
          security_valid: false,
          syntax_error: errorData.detail || '검증 요청 실패',
          structure_issues: [],
          security_violations: []
        })
      }
    } catch (error) {
      console.error('검증 오류:', error)
      setValidationResult({
        valid: false,
        syntax_valid: false,
        structure_valid: false,
        security_valid: false,
        syntax_error: '네트워크 오류',
        structure_issues: [],
        security_violations: []
      })
    } finally {
      setIsValidating(false)
    }
  }

  const handleContentChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newContent = e.target.value
    setContent(newContent)
  }

  const insertTemplate = () => {
    setContent(defaultPlaybookTemplate)
    setShowTemplate(false)
  }

  const downloadContent = () => {
    const blob = new Blob([content], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'playbook.yml'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file && (file.name.endsWith('.yml') || file.name.endsWith('.yaml'))) {
      const reader = new FileReader()
      reader.onload = (event) => {
        const fileContent = event.target?.result as string
        setContent(fileContent)
      }
      reader.readAsText(file)
    } else {
      alert('YAML 파일(.yml, .yaml)만 업로드 가능합니다.')
    }
    // 파일 입력 초기화
    e.target.value = ''
  }

  const getValidationIcon = () => {
    if (isValidating) {
      return <RefreshCw className="h-4 w-4 animate-spin text-blue-500" />
    }
    if (!validationResult) {
      return <Info className="h-4 w-4 text-gray-400" />
    }
    if (validationResult.valid) {
      return <CheckCircle className="h-4 w-4 text-green-500" />
    }
    return <XCircle className="h-4 w-4 text-red-500" />
  }

  const getValidationStatus = () => {
    if (isValidating) return "검증 중..."
    if (!validationResult) return "검증 대기"
    if (validationResult.valid) return "검증 통과"
    return "검증 실패"
  }

  return (
    <div className="space-y-4">
      {/* 도구 모음 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-2">
            {getValidationIcon()}
            <span className="text-sm font-medium">{getValidationStatus()}</span>
          </div>
          
          {validationResult && (
            <div className="flex space-x-1">
              <Badge 
                variant={validationResult.syntax_valid ? "default" : "destructive"}
                className="text-xs"
              >
                <Code className="h-3 w-3 mr-1" />
                문법
              </Badge>
              <Badge 
                variant={validationResult.structure_valid ? "default" : "destructive"}
                className="text-xs"
              >
                <FileText className="h-3 w-3 mr-1" />
                구조
              </Badge>
              <Badge 
                variant={validationResult.security_valid ? "default" : "destructive"}
                className="text-xs"
              >
                <Shield className="h-3 w-3 mr-1" />
                보안
              </Badge>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <label className="cursor-pointer">
            <Button variant="outline" size="sm" asChild>
              <span>
                <Upload className="h-4 w-4 mr-1" />
                파일 업로드
              </span>
            </Button>
            <input
              type="file"
              accept=".yml,.yaml"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
          
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowTemplate(!showTemplate)}
          >
            <FileText className="h-4 w-4 mr-1" />
            템플릿
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            onClick={downloadContent}
            disabled={!content.trim()}
          >
            <Download className="h-4 w-4 mr-1" />
            다운로드
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            onClick={validateContent}
            disabled={isValidating || !content.trim()}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${isValidating ? 'animate-spin' : ''}`} />
            검증
          </Button>
        </div>
      </div>

      {/* 템플릿 선택 */}
      {showTemplate && (
        <Alert>
          <FileText className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between">
            <span>기본 보안 점검 플레이북 템플릿을 사용하시겠습니까?</span>
            <div className="space-x-2">
              <Button size="sm" onClick={insertTemplate}>
                적용
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowTemplate(false)}>
                취소
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}

      {/* 메인 에디터 영역 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* 에디터 */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center justify-between">
                <span className="flex items-center">
                  <Code className="h-5 w-5 mr-2" />
                  YAML 에디터
                </span>
                <div className="flex items-center space-x-2">
                  <label className="flex items-center text-sm">
                    <input
                      type="checkbox"
                      checked={autoValidate}
                      onChange={(e) => setAutoValidate(e.target.checked)}
                      className="mr-1"
                    />
                    자동 검증
                  </label>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                ref={textareaRef}
                value={content}
                onChange={handleContentChange}
                placeholder="YAML 플레이북 내용을 입력하세요..."
                className="font-mono text-sm min-h-[500px] resize-none"
                readOnly={readOnly}
                style={{ height }}
              />
            </CardContent>
          </Card>
        </div>

        {/* 검증 결과 패널 */}
        <div className="space-y-4">
          {/* 검증 상태 요약 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center">
                <Shield className="h-5 w-5 mr-2" />
                검증 상태
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">전체 상태</span>
                <Badge variant={validationResult?.valid ? "default" : "destructive"}>
                  {validationResult?.valid ? "통과" : "실패"}
                </Badge>
              </div>
              
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="flex items-center">
                    <Code className="h-3 w-3 mr-1" />
                    YAML 문법
                  </span>
                  {validationResult?.syntax_valid ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="flex items-center">
                    <FileText className="h-3 w-3 mr-1" />
                    Ansible 구조
                  </span>
                  {validationResult?.structure_valid ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="flex items-center">
                    <Shield className="h-3 w-3 mr-1" />
                    보안 검사
                  </span>
                  {validationResult?.security_valid ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* 검증 결과 상세 */}
          {validationResult && !validationResult.valid && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center">
                  <AlertTriangle className="h-5 w-5 mr-2 text-yellow-500" />
                  문제점
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="syntax" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="syntax">문법</TabsTrigger>
                    <TabsTrigger value="structure">구조</TabsTrigger>
                    <TabsTrigger value="security">보안</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="syntax" className="mt-4">
                    {!validationResult.syntax_valid ? (
                      <Alert variant="destructive">
                        <XCircle className="h-4 w-4" />
                        <AlertDescription className="text-sm">
                          {validationResult.syntax_error}
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <Alert>
                        <CheckCircle className="h-4 w-4" />
                        <AlertDescription className="text-sm">
                          YAML 문법이 올바릅니다.
                        </AlertDescription>
                      </Alert>
                    )}
                  </TabsContent>
                  
                  <TabsContent value="structure" className="mt-4">
                    {validationResult.structure_issues.length > 0 ? (
                      <div className="space-y-2">
                        {validationResult.structure_issues.map((issue, index) => (
                          <Alert key={index} variant="destructive">
                            <XCircle className="h-4 w-4" />
                            <AlertDescription className="text-sm">
                              {issue}
                            </AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    ) : (
                      <Alert>
                        <CheckCircle className="h-4 w-4" />
                        <AlertDescription className="text-sm">
                          Ansible 플레이북 구조가 올바릅니다.
                        </AlertDescription>
                      </Alert>
                    )}
                  </TabsContent>
                  
                  <TabsContent value="security" className="mt-4">
                    {validationResult.security_violations.length > 0 ? (
                      <div className="space-y-2">
                        {validationResult.security_violations.map((violation, index) => (
                          <Alert key={index} variant="destructive">
                            <Shield className="h-4 w-4" />
                            <AlertDescription className="text-sm">
                              {violation}
                            </AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    ) : (
                      <Alert>
                        <CheckCircle className="h-4 w-4" />
                        <AlertDescription className="text-sm">
                          보안 검사를 통과했습니다.
                        </AlertDescription>
                      </Alert>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}