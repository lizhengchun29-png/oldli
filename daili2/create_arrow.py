from PIL import Image, ImageDraw

def create_down_arrow():
    # 创建一个 24x24 的透明图像
    size = (24, 24)
    image = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # 绘制箭头
    points = [(6, 10), (12, 16), (18, 10)]  # 三角形的三个点
    draw.polygon(points, fill=(74, 144, 226, 255))  # 使用主题蓝色
    
    # 保存图像
    image.save('down_arrow.png', 'PNG')

if __name__ == '__main__':
    create_down_arrow() 