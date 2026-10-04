import * as React from "react"
import { cva } from "class-variance-authority"
import { cn } from "../../lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold tracking-wide transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground shadow-xs",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground",
        destructive:
          "border-transparent bg-rose-500/15 text-rose-400 border-rose-500/30",
        outline: "text-foreground border-border",
        critical: "border-rose-500/30 bg-rose-500/15 text-rose-400 font-bold",
        high: "border-amber-500/30 bg-amber-500/15 text-amber-400 font-bold",
        medium: "border-orange-500/30 bg-orange-500/15 text-orange-300",
        low: "border-cyan-500/30 bg-cyan-500/15 text-cyan-400",
        secure: "border-emerald-500/30 bg-emerald-500/15 text-emerald-400 font-semibold",
        muted: "border-border bg-muted/60 text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({ className, variant, ...props }) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
