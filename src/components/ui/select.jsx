import React, { createContext, useContext, useState, useRef, useEffect } from "react"
const SelectContext = createContext()
export function Select({ value, onValueChange, children }) {
  const [open, setOpen] = useState(false)
  return <SelectContext.Provider value={{ value, onValueChange, open, setOpen }}>
    <div className="relative">{children}</div>
  </SelectContext.Provider>
}
export function SelectTrigger({ children, className }) {
  const { open, setOpen } = useContext(SelectContext)
  return (
    <button onClick={() => setOpen(!open)} className={`flex h-9 w-full items-center justify-between rounded-md border border-zinc-200 bg-transparent px-3 py-2 text-sm shadow-sm ring-offset-white placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-950 disabled:cursor-not-allowed disabled:opacity-50 dark:border-zinc-800 dark:ring-offset-zinc-950 dark:focus:ring-zinc-300 ${className}`}>
      {children}
    </button>
  )
}
export function SelectValue({ placeholder }) {
  const { value } = useContext(SelectContext)
  return <span>{value || placeholder}</span>
}
export function SelectContent({ children, className }) {
  const { open, setOpen } = useContext(SelectContext)
  if (!open) return null
  return (
    <div className={`absolute z-50 min-w-[8rem] overflow-hidden rounded-md border border-zinc-200 bg-white text-zinc-950 shadow-md animate-in fade-in-80 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-50 ${className}`}>
      <div className="p-1 w-full flex flex-col" onClick={() => setOpen(false)}>{children}</div>
    </div>
  )
}
export function SelectItem({ value, children, className }) {
  const { onValueChange } = useContext(SelectContext)
  return (
    <div
      onClick={() => onValueChange(value)}
      className={`relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none hover:bg-zinc-100 focus:bg-zinc-100 focus:text-zinc-900 data-[disabled]:pointer-events-none data-[disabled]:opacity-50 dark:hover:bg-zinc-800 dark:focus:bg-zinc-800 dark:focus:text-zinc-50 ${className}`}
    >
      {children}
    </div>
  )
}
