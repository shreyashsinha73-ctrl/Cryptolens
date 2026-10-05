import * as React from "react"
import { NavLink } from "react-router-dom"
import {
  LayoutDashboard,
  UploadCloud,
  Activity,
  ShieldAlert,
  Brain,
  FileText,
  HelpCircle,
  Shield,
  Server,
} from "lucide-react"
import { cn } from "../../lib/utils"

const NAV_GROUPS = [
  {
    group: "INSPECTION",
    items: [
      { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { path: "/upload", label: "Upload & analyze", icon: UploadCloud },
      { path: "/live", label: "Live monitor", icon: Activity },
      { path: "/testbed", label: "Testbed", icon: Server },
      { path: "/findings", label: "Findings & compliance", icon: ShieldAlert },
      { path: "/ai", label: "AI insights", icon: Brain },
      { path: "/reports", label: "Reports", icon: FileText },
    ],
  },
  // {
  //   group: "DOCUMENTATION",
  //   items: [
  //     { path: "/help", label: "Help & terminology", icon: HelpCircle },
  //   ],
  // },
]

export default function StitchSidebar({ isOpen, onClose }) {
  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs md:hidden"
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 bottom-0 z-50 w-60 border-r border-[#1F2639] bg-[#0A0D14] flex flex-col justify-between transition-transform duration-200 ease-in-out md:translate-x-0 select-none",
          isOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex flex-col flex-1 overflow-y-auto">
          {/* Brand header */}
          <div className="flex items-center gap-2.5 px-5 h-14 border-b border-[#1F2639]">
            {/* <div className="h-7 w-7 rounded-md bg-blue-600 flex items-center justify-center text-white shadow-xs">
              <Shield className="h-4 w-4" />
            </div> */}
            <div className="flex items-baseline gap-1.5">
              <span className="font-semibold text-sm tracking-tight text-white">
                CryptoLens
              </span>
              {/* <span className="text-[11px] font-mono text-gray-500">core</span> */}
            </div> 
          </div>

          {/* Nav items */}
          <div className="px-3 py-4 space-y-6">
            {NAV_GROUPS.map((sec) => (
              <div key={sec.group} className="space-y-1">
                <div className="px-3 text-[10px] font-semibold tracking-wider text-gray-500 uppercase font-mono">
                  {sec.group}
                </div>
                <div className="space-y-0.5 pt-1">
                  {sec.items.map((item) => {
                    const Icon = item.icon
                    return (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        onClick={() => {
                          if (onClose) onClose()
                        }}
                        className={({ isActive }) =>
                          cn(
                            "w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors text-left cursor-pointer",
                            isActive
                              ? "bg-[#1C2233] text-white font-semibold shadow-2xs"
                              : "text-gray-400 hover:bg-[#141824] hover:text-gray-200"
                          )
                        }
                      >
                        {({ isActive }) => (
                          <>
                            <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-blue-500" : "text-gray-500")} />
                            <span>{item.label}</span>
                          </>
                        )}
                      </NavLink>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer Zero Decryption Assurance card */}
        {/* <div className="p-3 border-t border-[#1F2639]">
          <div className="p-3 rounded-lg bg-[#0F121C] border border-[#1F2639] space-y-1">
            <div className="flex items-center gap-1.5 text-white text-[11px] font-semibold">
              <Shield className="h-3.5 w-3.5 text-blue-500 shrink-0" />
              <span>Zero Decryption Assurance</span>
            </div>
            <p className="text-[10px] text-gray-400 leading-relaxed font-sans">
              Passive wire inspection only. Cryptographic integrity strictly preserved.
            </p>
          </div>
        </div> */}
      </aside>
    </>
  )
}
