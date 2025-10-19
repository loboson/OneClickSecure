"use client"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { LayoutDashboard, FileText, Server, Clock, Settings, Terminal } from "lucide-react"
import { useEffect, useState } from "react"

interface SidebarProps {
  activeTab: string
  setActiveTab: (tab: string) => void
}

const baseMenuItems = [
  { id: "dashboard", label: "대시보드", icon: LayoutDashboard },
  { id: "playbooks", label: "플레이북", icon: FileText },
  { id: "inventory", label: "인벤토리", icon: Server },
  { id: "jobs", label: "작업 히스토리", icon: Clock },
  { id: "settings", label: "설정", icon: Settings },
]

export function Sidebar({ activeTab, setActiveTab }: SidebarProps) {
  const [playbooksEnabled, setPlaybooksEnabled] = useState(true) // 기본적으로 활성화
  const [isChecking, setIsChecking] = useState(false)

  // API 상태 확인 (선택적)
  useEffect(() => {
    const checkPlaybooksStatus = async () => {
      try {
        const response = await fetch('http://localhost:8000/')
        if (response.ok) {
          const data = await response.json()
          setPlaybooksEnabled(data.features?.playbooks !== false)
        }
      } catch (error) {
        console.log("API 상태 확인 실패 - 플레이북 기본 활성화")
        setPlaybooksEnabled(true) // 오류시에도 활성화
      } finally {
        setIsChecking(false)
      }
    }

    checkPlaybooksStatus()
  }, [])

  // 메뉴 항목은 항상 모든 항목 표시
  const menuItems = baseMenuItems

  return (
    <div className="w-64 bg-white border-r border-gray-200 flex flex-col">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center space-x-2">
          <Terminal className="h-8 w-8 text-blue-600" />
          <div className="flex flex-col">
            <h1 className="text-xl font-bold text-gray-900">Ansible Manager</h1>
            {!isChecking && (
              <span className="text-xs text-gray-500">
                {playbooksEnabled ? "풀 기능" : "인벤토리 전용"}
              </span>
            )}
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon
          
          return (
            <Button
              key={item.id}
              variant={activeTab === item.id ? "default" : "ghost"}
              className={cn(
                "w-full justify-start",
                activeTab === item.id 
                  ? "bg-blue-600 text-white hover:bg-blue-700" 
                  : "text-gray-700 hover:bg-gray-100"
              )}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon className="mr-3 h-4 w-4" />
              {item.label}
            </Button>
          )
        })}
      </nav>

      {/* 상태 표시 */}
      <div className="p-4 border-t border-gray-200">
        <div className="text-xs text-gray-500 space-y-1">
          <div className="flex items-center justify-between">
            <span>인벤토리:</span>
            <span className="text-green-600">활성</span>
          </div>
          <div className="flex items-center justify-between">
            <span>플레이북:</span>
            <span className={playbooksEnabled ? "text-green-600" : "text-gray-400"}>
              {isChecking ? "확인 중..." : (playbooksEnabled ? "활성" : "비활성")}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}