from PIL import Image, ImageDraw

def create_icon():
    # 创建一个 256x256 的图像，使用 RGBA 模式（支持透明）
    size = (256, 256)
    image = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # 绘制一个简单的代理图标
    # 外圈
    draw.ellipse([20, 20, 236, 236], outline=(30, 144, 255, 255), width=10)
    
    # 内部网络连接线
    draw.line([80, 80, 176, 176], fill=(30, 144, 255, 255), width=15)
    draw.line([80, 176, 176, 80], fill=(30, 144, 255, 255), width=15)
    
    # 保存为ICO文件
    image.save('icon.ico', format='ICO')

if __name__ == '__main__':
    create_icon() 