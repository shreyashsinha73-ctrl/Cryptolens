import * as React from "react"
import {
  Search,
  Lock,
  Moon,
  Sun,
  Bell,
  User,
  Menu,
  UploadCloud,
} from "lucide-react"
import { Button } from "../ui/button"
import { Badge } from "../ui/badge"
import { useTheme } from "../../context/useTheme"
import { useApp } from "../../context/AppContext"

export default function StitchHeader({ onToggleSidebar }) {
  const { toggleTheme, isDark } = useTheme()
  const { telemetry, handleUploadPcap, uploading } = useApp()
  const isConnected = telemetry?.isConnected
  const fileInputRef = React.useRef(null)

  return (
    <header className="h-14 border-b border-[#1F2639] bg-[#0A0D14]/90 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between gap-4 sticky top-0 z-30 select-none">
      <input
        type="file"
        ref={fileInputRef}
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f && handleUploadPcap) handleUploadPcap(f)
          e.target.value = ''
        }}
        accept=".pcap,.pcapng,.cap"
        className="hidden"
      />

      {/* Left: Mobile hamburger & Search bar */}
      <div className="flex items-center gap-3 flex-1 max-w-xl">
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggleSidebar}
          className="md:hidden text-gray-400 hover:text-white"
          aria-label="Toggle Menu"
        >
          <Menu className="h-4 w-4" />
        </Button>

        {/* Global Search Input matching Stitch design */}
        <div className="relative w-full max-w-md hidden sm:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            type="text"
            placeholder="Search traces, certificates, protocols..."
            className="w-full h-8 pl-8 pr-12 text-xs rounded-md bg-[#0F121C] border border-[#1F2639] text-gray-200 placeholder:text-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-all font-mono"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono text-gray-500 bg-[#161B26] px-1 py-0.5 rounded border border-[#242C3F] pointer-events-none">
            ⌘K
          </kbd>
        </div>

        {/* Metadata only badge */}
        {/* <Badge variant="outline" className="hidden lg:inline-flex items-center gap-1.5 py-0.5 px-2 text-[11px] font-mono text-gray-400 border-[#1F2639] bg-[#0F121C]"> */}
          {/* <Lock className="h-3 w-3 text-gray-400" /> */}
          {/* <span>Metadata only</span> */}
        {/* </Badge > */}
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
        {/* Upload PCAP Button in Header */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="border-[#1F2639] bg-[#0F121C] hover:bg-[#161B26] text-gray-200 text-xs h-8 px-3 gap-1.5 cursor-pointer"
        >
          <UploadCloud className="h-3.5 w-3.5 text-blue-400" />
          <span>{uploading ? 'Uploading...' : 'Upload PCAP'}</span>
        </Button>

        {/* /* Connected Daemon pill */
        /* <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#0F121C] border border-[#1F2639] text-[11px] font-mono">
          <span className={`h-1.5 w-1.5 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
          <span className={isConnected ? 'text-emerald-400' : 'text-amber-400'}>
            {isConnected ? 'Connected daemon v2.4.1' : 'Daemon connecting...'}
          </span>
        </div> */ }

        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleTheme}
          className="text-gray-400 hover:text-white"
          aria-label="Toggle Theme"
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        {/* Notification bell */}
        <Button
          variant="ghost"
          size="icon"
          className="text-gray-400 hover:text-white relative"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-blue-500" />
        </Button>

        {/* User profile capsule matching Stitch */}
        <div className="flex items-center gap-2 pl-2 border-l border-[#1F2639]">
          <div className="hidden md:flex flex-col text-right">
            {/* <span className="text-xs font-semibold text-gray-200 leading-none">Lab Station #04</span> */}
            {/* <span className="text-[10px] text-gray-500 font-mono leading-tight mt-0.5">SOC Operator</span> */}
          </div>
          <div className="h-8 w-8 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <User className="h-4 w-4" />
          </div>
        </div>
      </div>
    </header>
  )
}
