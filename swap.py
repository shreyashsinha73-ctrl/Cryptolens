import re

with open('src/App.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

pattern = r'({\/\* Middle Row: Charts \*\/}.*?<div className="grid grid-cols-1 lg:grid-cols-3 gap-6 px-6 mt-6">)(.*?)({\/\* Bottom Row: Tables \*\/})'

match = re.search(pattern, content, re.DOTALL)
if match:
    middle_row_content = match.group(2)
    parts = middle_row_content.split('{/* Right Chart (span 1): Radial Score Dial */}')
    
    left_chart = parts[0]
    right_chart = '{/* Right Chart (span 1): Radial Score Dial */}' + parts[1]
    
    # Change grid classes
    right_chart = right_chart.replace('className="bg-white p-6 shadow-md flex flex-col h-[350px]"', 'className="lg:col-span-1 bg-white p-6 shadow-md flex flex-col h-[350px]"')
    left_chart = left_chart.replace('className="lg:col-span-2 bg-[#172b4d]  p-6 shadow-md flex flex-col h-[350px]"', 'className="lg:col-span-2 bg-white p-6 shadow-md flex flex-col h-[350px]"')
    # Actually wait, maybe there was no className="... " in the replace string? Let's be safer.
    
    # Actually, the string was `className="bg-white p-6 shadow-md flex flex-col h-[350px]"` in right chart.
    if 'className="bg-white' in right_chart:
        right_chart = right_chart.replace('className="bg-white', 'className="lg:col-span-1 bg-white')
    if 'bg-[#172b4d]' in left_chart:
        left_chart = left_chart.replace('bg-[#172b4d]', 'bg-white')
    
    left_chart = left_chart.replace('text-white text-xl font-bold', 'text-slate-800 text-xl font-bold')
    left_chart = left_chart.replace('stroke="#627192"', 'stroke="#333333"')
    left_chart = left_chart.replace("fill: '#8898aa'", "fill: '#333333'")
    left_chart = left_chart.replace("backgroundColor: '#112240'", "backgroundColor: '#f8fafc'")
    left_chart = left_chart.replace("color: '#fff'", "color: '#1e293b'")
    left_chart = left_chart.replace("itemStyle={{ color: '#ffffff' }}", "itemStyle={{ color: '#0f172a' }}")
    left_chart = left_chart.replace("fill: 'rgba(255, 255, 255, 0.05)'", "fill: 'rgba(0, 0, 0, 0.05)'")
    
    new_middle_row = match.group(1) + '\n          ' + right_chart.strip() + '\n\n          ' + left_chart.strip() + '\n        </div>\n\n        ' + match.group(3)
    
    content = content.replace(match.group(0), new_middle_row)
    
    with open('src/App.jsx', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Success')
else:
    print('Failed to find match')
