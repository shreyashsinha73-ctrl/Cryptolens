import React, { createContext, useContext, useState } from "react"
const TabsContext = createContext()
export function Tabs({ defaultValue, value, onValueChange, children, className }) {
  const [tab, setTab] = useState(defaultValue)
  const activeTab = value !== undefined ? value : tab
  const setActiveTab = onValueChange || setTab
  return <TabsContext.Provider value={{ activeTab, setActiveTab }}><div className={className}>{children}</div></TabsContext.Provider>
}
export function TabsList({ children, className }) {
  return <div className={`inline-flex h-9 items-center justify-center rounded-lg bg-zinc-100 p-1 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 ${className}`}>{children}</div>
}
export function TabsTrigger({ value, children, className }) {
  const { activeTab, setActiveTab } = useContext(TabsContext)
  const isActive = activeTab === value
  return (
    <button
      onClick={() => setActiveTab(value)}
      className={`inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium ring-offset-white transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 ${isActive ? "bg-white text-zinc-950 shadow dark:bg-zinc-950 dark:text-zinc-50" : "hover:text-zinc-900 hover:dark:text-zinc-50"} ${className}`}
    >
      {children}
    </button>
  )
}
export function TabsContent({ value, children, className }) {
  const { activeTab } = useContext(TabsContext)
  if (activeTab !== value) return null
  return <div className={`mt-2 ring-offset-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-950 focus-visible:ring-offset-2 dark:ring-offset-zinc-950 dark:focus-visible:ring-zinc-300 ${className}`}>{children}</div>
}
