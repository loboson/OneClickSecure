"use client"

import { useState } from "react"
import { Sidebar } from "@/components/ui/sidebar"
import { Dashboard } from "@/components/ui/dashboard"
import { Playbooks } from "@/components/ui/playbooks"
import { Inventory } from "@/components/ui/inventory"
import { Jobs } from "@/components/ui/jobs"
import { Settings } from "@/components/ui/settings"

export default function Home() {
  const [activeTab, setActiveTab] = useState("dashboard")

  const renderContent = () => {
    switch (activeTab) {
      case "dashboard":
        return <Dashboard />
      case "playbooks":
        return <Playbooks />
      case "inventory":
        return <Inventory />
      case "jobs":
        return <Jobs />
      case "settings":
        return <Settings />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className="flex h-screen bg-gray-50">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <main className="flex-1 overflow-auto">{renderContent()}</main>
    </div>
  )
}