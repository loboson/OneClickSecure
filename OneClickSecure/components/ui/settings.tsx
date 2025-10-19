"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { SettingsIcon, Save, Key, Bell, Shield } from "lucide-react"

export function Settings() {
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">설정</h1>
      </div>

      <Tabs defaultValue="general" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="general">일반</TabsTrigger>
          <TabsTrigger value="auth">인증</TabsTrigger>
          <TabsTrigger value="notifications">알림</TabsTrigger>
          <TabsTrigger value="security">보안</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <SettingsIcon className="h-5 w-5" />
                <span>일반 설정</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ansible-host">Ansible 호스트</Label>
                  <Input id="ansible-host" placeholder="localhost" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ansible-port">Ansible 포트</Label>
                  <Input id="ansible-port" placeholder="22" />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="inventory-path">인벤토리 파일 경로</Label>
                <Input id="inventory-path" placeholder="/etc/ansible/hosts" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="playbook-path">플레이북 디렉토리</Label>
                <Input id="playbook-path" placeholder="/etc/ansible/playbooks" />
              </div>

              <div className="flex items-center space-x-2">
                <Switch id="verbose-mode" />
                <Label htmlFor="verbose-mode">상세 로그 모드</Label>
              </div>

              <div className="flex items-center space-x-2">
                <Switch id="auto-backup" />
                <Label htmlFor="auto-backup">자동 백업 활성화</Label>
              </div>

              <Button className="w-full md:w-auto">
                <Save className="w-4 h-4 mr-2" />
                설정 저장
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="auth" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Key className="h-5 w-5" />
                <span>인증 설정</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="ssh-key">SSH 개인키 경로</Label>
                <Input id="ssh-key" placeholder="~/.ssh/id_rsa" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="ssh-user">기본 SSH 사용자</Label>
                <Input id="ssh-user" placeholder="ansible" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="vault-password">Ansible Vault 비밀번호</Label>
                <Input id="vault-password" type="password" placeholder="••••••••" />
              </div>

              <div className="flex items-center space-x-2">
                <Switch id="ssh-agent" />
                <Label htmlFor="ssh-agent">SSH Agent 사용</Label>
              </div>

              <div className="flex items-center space-x-2">
                <Switch id="host-key-checking" />
                <Label htmlFor="host-key-checking">호스트 키 검증</Label>
              </div>

              <Button className="w-full md:w-auto">
                <Save className="w-4 h-4 mr-2" />
                인증 설정 저장
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Bell className="h-5 w-5" />
                <span>알림 설정</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label>작업 완료 알림</Label>
                    <p className="text-sm text-muted-foreground">플레이북 실행이 완료되면 알림을 받습니다</p>
                  </div>
                  <Switch />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>작업 실패 알림</Label>
                    <p className="text-sm text-muted-foreground">플레이북 실행이 실패하면 알림을 받습니다</p>
                  </div>
                  <Switch />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>호스트 오프라인 알림</Label>
                    <p className="text-sm text-muted-foreground">호스트가 오프라인 상태가 되면 알림을 받습니다</p>
                  </div>
                  <Switch />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">알림 이메일</Label>
                <Input id="email" type="email" placeholder="admin@example.com" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="webhook">Webhook URL</Label>
                <Input id="webhook" placeholder="https://hooks.slack.com/..." />
              </div>

              <Button className="w-full md:w-auto">
                <Save className="w-4 h-4 mr-2" />
                알림 설정 저장
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>보안 설정</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label>2단계 인증</Label>
                    <p className="text-sm text-muted-foreground">로그인 시 추가 보안 인증을 요구합니다</p>
                  </div>
                  <Switch />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>세션 타임아웃</Label>
                    <p className="text-sm text-muted-foreground">비활성 상태에서 자동 로그아웃됩니다</p>
                  </div>
                  <Switch />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>감사 로그</Label>
                    <p className="text-sm text-muted-foreground">모든 사용자 활동을 기록합니다</p>
                  </div>
                  <Switch />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="session-timeout">세션 타임아웃 (분)</Label>
                <Input id="session-timeout" type="number" placeholder="30" />
              </div>

              <div className="space-y-2">
                <Label htmlFor="allowed-ips">허용된 IP 주소</Label>
                <Textarea id="allowed-ips" placeholder="192.168.1.0/24&#10;10.0.0.0/8" rows={3} />
              </div>

              <Button className="w-full md:w-auto">
                <Save className="w-4 h-4 mr-2" />
                보안 설정 저장
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
