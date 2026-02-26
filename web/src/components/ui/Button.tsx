import type { ButtonHTMLAttributes } from 'react'

type Variant = 'primary' | 'secondary' | 'danger'

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
}

const variants: Record<Variant, string> = {
  primary: 'bg-blue-500/20 text-blue-200 border-blue-400/40 hover:bg-blue-500/30',
  secondary: 'bg-slate-800 text-slate-100 border-slate-600 hover:bg-slate-700',
  danger: 'bg-rose-500/20 text-rose-200 border-rose-400/40 hover:bg-rose-500/30',
}

export function Button({ className = '', variant = 'primary', type = 'button', ...props }: Props) {
  return (
    <button
      type={type}
      className={`inline-flex min-h-11 items-center justify-center rounded-lg border px-4 py-2 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    />
  )
}
