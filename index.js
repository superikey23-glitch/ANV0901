const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'user-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 
    }
});

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, 'database.sqlite'),
});

const User = sequelize.define('User', {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    fullName: { type: DataTypes.STRING, allowNull: true },
    photo: { type: DataTypes.STRING, allowNull: true },
    role: { type: DataTypes.ENUM('admin', 'user'), defaultValue: 'user' }
});

const Perfume = sequelize.define('Perfume', {
    name: { type: DataTypes.STRING, allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
    volume: { type: DataTypes.INTEGER, allowNull: false }, 
    gender: { type: DataTypes.ENUM('мужской', 'женский', 'унисекс'), allowNull: false },
    inStock: { type: DataTypes.BOOLEAN, defaultValue: true },
});

const Brand = sequelize.define('Brand', {
    name: { type: DataTypes.STRING, allowNull: false },
    country: { type: DataTypes.STRING },
});

const Category = sequelize.define('Category', {
    name: { type: DataTypes.STRING, allowNull: false },
});

const Supplier = sequelize.define('Supplier', {
    name: { type: DataTypes.STRING, allowNull: false },
    contact: { type: DataTypes.STRING },
});

Perfume.belongsTo(Brand);
Perfume.belongsTo(Category);
Perfume.belongsTo(Supplier);
Brand.hasMany(Perfume);
Category.hasMany(Perfume);
Supplier.hasMany(Perfume);

const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.session.user || !roles.includes(req.session.user.role)) {
            return res.status(403).send('Доступ запрещен');
        }
        next();
    };
};

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = await User.findOne({ where: { username } });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = {
                id: user.id,
                username: user.username,
                fullName: user.fullName,
                photo: user.photo,
                role: user.role
            };
            res.redirect('/');
        } else {
            res.render('login', { error: 'Неверные учетные данные' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/register', async (req, res) => {
    const { username, password, fullName, role = 'user' } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, password: hashedPassword, fullName, role });
        res.redirect('/login');
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { error: 'Ошибка регистрации' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', requireAuth, async (req, res) => {
    try {
        const perfumes = await Perfume.findAll({
            include: [Brand, Category, Supplier],
            limit: 6
        });
        res.render('index', { 
            perfumes,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Error fetching perfumes:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/users', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: { exclude: ['password'] },
            order: [['createdAt', 'DESC']]
        });
        res.render('users', {
            users,
            user: req.session.user
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/add-user', requireAuth, requireRole(['admin']), (req, res) => {
    res.render('add-user', { user: req.session.user });
});

app.post('/add-user', requireAuth, requireRole(['admin']), upload.single('photo'), async (req, res) => {
    try {
        const { username, password, fullName, role } = req.body;
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const photo = req.file ? '/uploads/' + req.file.filename : null;

        await User.create({
            username,
            password: hashedPassword,
            fullName,
            photo,
            role
        });

        res.redirect('/users');
    } catch (error) {
        console.error('Error adding user:', error);
        res.render('add-user', { 
            error: 'Ошибка при добавлении пользователя',
            user: req.session.user 
        });
    }
});

app.get('/edit-user/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.params.id;
        const userToEdit = await User.findByPk(userId, {
            attributes: { exclude: ['password'] }
        });

        if (!userToEdit) {
            return res.status(404).send('Пользователь не найден');
        }

        if (req.session.user.role !== 'admin' && req.session.user.id !== parseInt(userId)) {
            return res.status(403).send('Доступ запрещен');
        }

        res.render('edit-user', {
            userToEdit,
            user: req.session.user
        });
    } catch (error) {
        console.error('Error fetching user for edit:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/edit-user/:id', requireAuth, upload.single('photo'), async (req, res) => {
    try {
        const userId = req.params.id;
        const { username, fullName, role, removePhoto } = req.body;

        if (req.session.user.role !== 'admin' && req.session.user.id !== parseInt(userId)) {
            return res.status(403).send('Доступ запрещен');
        }

        const updateData = {
            username,
            fullName
        };

        if (req.session.user.role === 'admin') {
            updateData.role = role;
        }

        if (removePhoto === 'true') {
            updateData.photo = null;
        } else if (req.file) {
            updateData.photo = '/uploads/' + req.file.filename;
        }

        await User.update(updateData, {
            where: { id: userId }
        });

        if (req.session.user.id === parseInt(userId)) {
            const updatedUser = await User.findByPk(userId, {
                attributes: { exclude: ['password'] }
            });
            req.session.user = {
                id: updatedUser.id,
                username: updatedUser.username,
                fullName: updatedUser.fullName,
                photo: updatedUser.photo,
                role: updatedUser.role
            };
        }

        res.redirect(req.session.user.role === 'admin' ? '/users' : '/profile');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/delete-user/:id', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const userId = req.params.id;
        
        if (req.session.user.id === parseInt(userId)) {
            return res.status(400).send('Нельзя удалить свой аккаунт');
        }

        await User.destroy({
            where: { id: userId }
        });

        res.redirect('/users');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/profile', requireAuth, async (req, res) => {
    try {
        const userProfile = await User.findByPk(req.session.user.id, {
            attributes: { exclude: ['password'] }
        });
        res.render('profile', {
            userProfile,
            user: req.session.user
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/catalog', requireAuth, async (req, res) => {
    try {
        const perfumes = await Perfume.findAll({
            include: [Brand, Category, Supplier],
        });
        res.render('catalog', { 
            perfumes,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Error fetching perfumes:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/cart', requireAuth, (req, res) => {
    const cartItems = [];
    const totalAmount = 0;
    
    res.render('cart', { 
        cartItems,
        totalAmount,
        user: req.session.user 
    });
});

app.get('/add-brand', requireAuth, requireRole(['admin']), (req, res) => {
    res.render('add-brand', { user: req.session.user });
});

app.get('/add-category', requireAuth, requireRole(['admin']), (req, res) => {
    res.render('add-category', { user: req.session.user });
});

app.get('/add-supplier', requireAuth, requireRole(['admin']), (req, res) => {
    res.render('add-supplier', { user: req.session.user });
});

app.get('/add-perfume', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const brands = await Brand.findAll();
        const categories = await Category.findAll();
        const suppliers = await Supplier.findAll();
        res.render('add-perfume', { 
            brands, 
            categories, 
            suppliers,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/edit-perfume/:id', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const perfumeId = req.params.id;
        const perfume = await Perfume.findByPk(perfumeId, {
            include: [Brand, Category, Supplier],
        });
        if (!perfume) {
            return res.status(404).send('Perfume not found');
        }
        const brands = await Brand.findAll();
        const categories = await Category.findAll();
        const suppliers = await Supplier.findAll();
        res.render('edit-perfume', { 
            perfume, 
            brands, 
            categories, 
            suppliers,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Error fetching perfume for edit:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-brand', requireAuth, requireRole(['admin']), async (req, res) => {
    const { name, country } = req.body;
    if (name) {
        await Brand.create({ name, country });
    }
    res.redirect('/');
});

app.post('/add-category', requireAuth, requireRole(['admin']), async (req, res) => {
    const { name } = req.body;
    if (name) {
        await Category.create({ name });
    }
    res.redirect('/');
});

app.post('/add-supplier', requireAuth, requireRole(['admin']), async (req, res) => {
    const { name, contact } = req.body;
    if (name) {
        await Supplier.create({ name, contact });
    }
    res.redirect('/');
});

app.post('/add-perfume', requireAuth, requireRole(['admin']), async (req, res) => {
    const { name, price, volume, gender, brandId, categoryId, supplierId } = req.body;

    if (name && price && volume && gender && brandId && categoryId && supplierId) {
        try {
            await Perfume.create({
                name,
                price: parseFloat(price),
                volume: parseInt(volume),
                gender,
                BrandId: brandId,
                CategoryId: categoryId,
                SupplierId: supplierId,
            });
            res.redirect('/');
        } catch (error) {
            console.error('Error adding perfume:', error);
            res.status(500).send('Internal Server Error');
        }
    } else {
        res.status(400).send('All fields are required');
    }
});

app.post('/delete-perfume/:id', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const perfumeId = req.params.id;
        await Perfume.destroy({
            where: { id: perfumeId },
        });
        res.redirect('/');
    } catch (error) {
        console.error('Error deleting perfume:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/edit-perfume/:id', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const perfumeId = req.params.id;
        const { name, price, volume, gender, brandId, categoryId, supplierId } = req.body;

        await Perfume.update(
            {
                name,
                price: parseFloat(price),
                volume: parseInt(volume),
                gender,
                BrandId: brandId,
                CategoryId: categoryId,
                SupplierId: supplierId
            },
            { where: { id: perfumeId } }
        );
        res.redirect('/');
    } catch (error) {
        console.error('Error updating perfume:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('*', (req, res) => {
    res.status(404).render('404', { 
        user: req.session.user || null 
    });
});

(async () => {
    try {
        await sequelize.sync({ force: true });

        const hashedAdminPassword = await bcrypt.hash('admin123', 10);
        const hashedUserPassword = await bcrypt.hash('user123', 10);

        await User.create({
            username: 'admin',
            password: hashedAdminPassword,
            fullName: 'Администратор Системы',
            role: 'admin'
        });

        await User.create({
            username: 'user',
            password: hashedUserPassword,
            fullName: 'Обычный Пользователь',
            role: 'user'
        });

        const brand1 = await Brand.create({ name: 'Chanel', country: 'Франция' });
        const brand2 = await Brand.create({ name: 'Dior', country: 'Франция' });
        const brand3 = await Brand.create({ name: 'Guerlain', country: 'Франция' });

        const category1 = await Category.create({ name: 'Цветочные' });
        const category2 = await Category.create({ name: 'Восточные' });
        const category3 = await Category.create({ name: 'Древесные' });

        const supplier1 = await Supplier.create({ name: 'Luxury Perfumes', contact: 'info@luxury-perfumes.com' });
        const supplier2 = await Supplier.create({ name: 'French Fragrances', contact: 'contact@french-fragrances.fr' });

        await Perfume.create({
            name: 'Chanel No. 5',
            price: 8900,
            volume: 100,
            gender: 'женский',
            BrandId: brand1.id,
            CategoryId: category1.id,
            SupplierId: supplier1.id
        });

        await Perfume.create({
            name: 'Dior Sauvage',
            price: 7500,
            volume: 100,
            gender: 'мужской',
            BrandId: brand2.id,
            CategoryId: category3.id,
            SupplierId: supplier1.id
        });

        await Perfume.create({
            name: 'Shalimar',
            price: 9200,
            volume: 100,
            gender: 'унисекс',
            BrandId: brand3.id,
            CategoryId: category2.id,
            SupplierId: supplier2.id
        });

        app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
    } catch (error) {
        console.error('Error initializing the application:', error);
    }
})();