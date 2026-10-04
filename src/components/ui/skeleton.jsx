import React from "react"
function Skeleton({ className, ...props }) {
  return (
    <div className={`animate-pulse rounded-md bg-zinc-900/10 dark:bg-zinc-50/10 ${className}`} {...props} />
  )
}
export { Skeleton }
